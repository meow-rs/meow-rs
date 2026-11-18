#![cfg(feature = "vless")]
//! Integration tests for the VLESS outbound proxy adapter (§H, M1.B-2).
//!
//! Uses an embedded mock VLESS server over plain TCP — no external binaries
//! required.  The mock parses the VLESS request header, validates the UUID,
//! writes the response header, then relays TCP traffic to the echo target.
//!
//! Tests that require a real `xray` binary (H3 UDP, H4 Vision, H6 delay-probe)
//! check for the binary at runtime and emit a `SKIP:` line when absent.
//! Set `MIHOMO_REQUIRE_INTEGRATION_BINS=1` to fail instead of skip.

#[cfg(feature = "vless")]
mod vless_tests {
    use meow_common::{Metadata, Network, ProxyAdapter};
    use meow_proxy::dialer::DirectDialer;
    use meow_proxy::{TransportChain, VlessAdapter};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{timeout, Duration};

    /// UUID for all VLESS integration tests: b831381d-6324-4d53-ad4f-8cda48b30811
    pub(super) const TEST_UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    /// A different UUID — used to simulate a server that rejects the connection.
    const WRONG_UUID: [u8; 16] = [0xff; 16];

    pub(super) const TIMEOUT: Duration = Duration::from_secs(10);

    // ─── TCP echo server ──────────────────────────────────────────────────────

    pub(super) async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (addr, handle)
    }

    // ─── Mock VLESS server ────────────────────────────────────────────────────

    /// Parse the VLESS request header from `stream`.
    ///
    /// Wire format (upstream: `transport/vless/encoding.go::EncodeRequestHeader`):
    /// ```text
    /// version(1=0x00)  uuid(16)  addon_length(1)  addon(N)
    /// cmd(1)  port(2,BE)  addr_type(1)  addr
    /// ```
    /// NOTE: `port` comes BEFORE `addr_type` — the VLESS/VMess convention.
    pub(super) async fn read_vless_header<S: AsyncReadExt + Unpin>(
        stream: &mut S,
    ) -> std::io::Result<([u8; 16], u8, SocketAddr)> {
        // version
        let mut version = [0u8; 1];
        stream.read_exact(&mut version).await?;
        if version[0] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("mock vless: unexpected version byte {:#04x}", version[0]),
            ));
        }

        // uuid (16 bytes)
        let mut uuid = [0u8; 16];
        stream.read_exact(&mut uuid).await?;

        // addon
        let mut addon_len = [0u8; 1];
        stream.read_exact(&mut addon_len).await?;
        if addon_len[0] > 0 {
            let mut addon = vec![0u8; addon_len[0] as usize];
            stream.read_exact(&mut addon).await?;
        }

        // cmd
        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;

        // port (big-endian) — comes BEFORE addr_type per VLESS wire format
        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).await?;
        let port = u16::from_be_bytes(port_bytes);

        // addr_type + address
        let mut addr_type = [0u8; 1];
        stream.read_exact(&mut addr_type).await?;
        let addr = match addr_type[0] {
            0x01 => {
                // IPv4
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
            }
            0x02 => {
                // Domain
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                let domain_str = String::from_utf8_lossy(&domain);
                // The mock can only relay to loopback — it cannot resolve arbitrary domains.
                let ip = match domain_str.as_ref() {
                    "localhost" | "127.0.0.1" => IpAddr::V4(Ipv4Addr::LOCALHOST),
                    other => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            format!("mock vless: cannot resolve '{other}'"),
                        ));
                    }
                };
                SocketAddr::new(ip, port)
            }
            0x03 => {
                // IPv6
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(ip)), port)
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("mock vless: unknown addr_type {other:#04x}"),
                ));
            }
        };

        Ok((uuid, cmd[0], addr))
    }

    /// Start an in-process mock VLESS server bound to a random loopback port.
    ///
    /// For each connection the server:
    /// 1. Reads the VLESS request header.
    /// 2. Closes without response if the UUID does not match `expected_uuid`.
    /// 3. Writes the VLESS response header `[0x00, 0x00]`.
    /// 4. Relays TCP traffic to `target_addr` (cmd = 0x01).
    pub(super) async fn start_mock_vless_server(
        expected_uuid: [u8; 16],
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_uuid = Arc::new(expected_uuid);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                let expected_uuid = Arc::clone(&expected_uuid);
                tokio::spawn(async move {
                    let Ok((uuid, cmd, target_addr)) = read_vless_header(&mut tcp).await else {
                        eprintln!("mock vless: header parse error");
                        return;
                    };

                    // UUID mismatch — close without response (simulates xray behaviour).
                    if uuid != *expected_uuid {
                        eprintln!("mock vless: UUID mismatch — closing");
                        return;
                    }

                    // VLESS response header: version=0x00, addon_length=0x00.
                    if tcp.write_all(&[0x00, 0x00]).await.is_err() {
                        return;
                    }

                    match cmd {
                        0x01 => {
                            // TCP CONNECT relay
                            match TcpStream::connect(target_addr).await {
                                Ok(mut target) => {
                                    let _ =
                                        tokio::io::copy_bidirectional(&mut tcp, &mut target).await;
                                }
                                Err(e) => {
                                    eprintln!("mock vless: relay connect to {target_addr}: {e}");
                                }
                            }
                        }
                        other => {
                            eprintln!("mock vless: unsupported cmd {other:#04x}");
                        }
                    }
                });
            }
        });

        (addr, handle)
    }

    // ─── H1: TCP plain VLESS round-trip ──────────────────────────────────────

    /// H1: Send 1 KiB through a plain VLESS connection; assert echoed bytes match.
    ///
    /// No outer transport layer — tests the core VLESS header exchange and
    /// bidirectional relay.  Acceptance criterion #3.
    #[tokio::test]
    async fn vless_tcp_plain_roundtrip() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let mut conn = result
            .expect("vless_tcp_plain_roundtrip: dial_tcp timed out")
            .expect("vless_tcp_plain_roundtrip: dial_tcp failed");

        let payload: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        conn.write_all(&payload).await.expect("write failed");
        conn.flush().await.expect("flush failed");

        let mut buf = vec![0u8; payload.len()];
        conn.read_exact(&mut buf).await.expect("read_exact failed");
        assert_eq!(buf, payload, "TCP echo mismatch");
    }

    // ─── H2: Large-payload round-trip ────────────────────────────────────────

    /// H2: Send 64 KiB; assert echoed bytes match.
    ///
    /// Stresses the VLESS framing path and the relay buffer in the mock.
    #[tokio::test]
    async fn vless_tcp_large_payload_roundtrip() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless-large",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let mut conn = result
            .expect("large_payload: dial_tcp timed out")
            .expect("large_payload: dial_tcp failed");

        let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        conn.write_all(&payload).await.expect("write failed");
        conn.flush().await.expect("flush failed");

        let mut buf = vec![0u8; payload.len()];
        conn.read_exact(&mut buf).await.expect("read_exact failed");
        assert_eq!(buf, payload, "64 KiB echo mismatch");
    }

    // ─── H3: Concurrent connections ───────────────────────────────────────────

    /// H3: Five simultaneous VLESS connections all complete their echo round-trip.
    ///
    /// Guards against state leakage between concurrent connections (shared UUID
    /// reference, header parse races).
    #[tokio::test]
    async fn vless_tcp_concurrent_connections() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = Arc::new(VlessAdapter::new(
            "test-vless-concurrent",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        ));

        let mut handles = Vec::new();
        for i in 0u8..5 {
            let adapter = Arc::clone(&adapter);
            let handle = tokio::spawn(async move {
                let metadata = Metadata {
                    network: Network::Tcp,
                    dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    dst_port: echo_addr.port(),
                    ..Default::default()
                };
                let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
                let mut conn = result
                    .expect("concurrent: dial_tcp timed out")
                    .expect("concurrent: dial_tcp failed");

                let payload = vec![i; 128];
                conn.write_all(&payload)
                    .await
                    .expect("concurrent: write failed");
                conn.flush().await.expect("concurrent: flush failed");

                let mut buf = vec![0u8; 128];
                conn.read_exact(&mut buf)
                    .await
                    .expect("concurrent: read_exact failed");
                assert_eq!(buf, payload, "concurrent echo mismatch for i={i}");
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.expect("concurrent task panicked");
        }
    }

    // ─── H4: Second small payload (back-to-back writes on same connection) ───

    /// H4: Two sequential payloads on the same connection — guards against
    ///     state corruption between writes (e.g. response header re-read).
    #[tokio::test]
    async fn vless_tcp_sequential_writes_same_connection() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless-seq",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let mut conn = result
            .expect("seq: dial_tcp timed out")
            .expect("seq: dial_tcp failed");

        // First payload
        let payload1 = b"hello vless round one";
        conn.write_all(payload1).await.expect("write1 failed");
        conn.flush().await.expect("flush1 failed");
        let mut buf1 = vec![0u8; payload1.len()];
        conn.read_exact(&mut buf1).await.expect("read1 failed");
        assert_eq!(&buf1, payload1, "echo mismatch round 1");

        // Second payload on the same connection
        let payload2 = b"hello vless round two";
        conn.write_all(payload2).await.expect("write2 failed");
        conn.flush().await.expect("flush2 failed");
        let mut buf2 = vec![0u8; payload2.len()];
        conn.read_exact(&mut buf2).await.expect("read2 failed");
        assert_eq!(&buf2, payload2, "echo mismatch round 2");
    }

    // ─── H5: Wrong UUID → clean error ────────────────────────────────────────

    /// H5: UUID mismatch causes the server to close the connection without
    ///     sending a VLESS response header.  The client must surface a clean
    ///     `Err` — not a panic or a raw `UnexpectedEof` propagated to the
    ///     caller without context.
    ///
    /// Upstream: xray-core closes silently on UUID mismatch.
    /// NOT silent — we surface "server closed after header" with context.
    /// Class B per ADR-0002 (same destination, wrong credential).
    #[tokio::test]
    async fn vless_wrong_uuid_fails_cleanly() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        // Mock expects TEST_UUID; client sends WRONG_UUID.
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless-wrong-uuid",
            "127.0.0.1",
            vless_addr.port(),
            WRONG_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let inner = result.expect("wrong-uuid: dial_tcp timed out (expected prompt rejection)");
        // With lazy response reading, dial_tcp succeeds but the first read
        // triggers the error when the server closes after seeing wrong UUID.
        match inner {
            Ok(mut conn) => {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 1];
                let read_result = timeout(TIMEOUT, conn.read(&mut buf)).await;
                let read_inner =
                    read_result.expect("wrong-uuid: read timed out (expected prompt error)");
                let err = read_inner
                    .expect_err("wrong-uuid: read must return Err after server rejection");
                let err_str = err.to_string();
                assert!(
                    err_str.contains("closed")
                        || err_str.contains("eof")
                        || err_str.contains("EOF")
                        || err_str.contains("Eof")
                        || err_str.contains("server")
                        || err_str.contains("UUID"),
                    "error must describe the cause, got: {err_str}"
                );
            }
            Err(e) => {
                // Also acceptable if dial_tcp itself fails.
                let err_str = e.to_string();
                assert!(
                    err_str.contains("server closed")
                        || err_str.contains("UUID")
                        || err_str.contains("server config"),
                    "error must describe the cause, got: {err_str}"
                );
            }
        }
    }

    // ─── H6: health() is accessible after dial (ProxyHealth API guard) ────────

    /// H6 (lite): Assert that `adapter.health()` is accessible without panic after
    ///           a successful `dial_tcp`.  Full history-array validation requires
    ///           the api-delay-endpoints integration harness (cross-spec, M2 scope).
    #[tokio::test]
    async fn vless_health_accessible_after_dial() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless-health",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let mut conn = result
            .expect("health: dial_tcp timed out")
            .expect("health: dial_tcp failed");

        // Write and drain to confirm the connection is live.
        conn.write_all(b"ping").await.expect("ping write failed");
        conn.flush().await.expect("ping flush failed");
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.expect("ping read failed");
        assert_eq!(&buf, b"ping");

        // ProxyHealth must be accessible — no panic.
        let _health = adapter.health();
    }

    // ─── H7: VLESS over XHTTP end-to-end round-trip ───────────────────────────

    // XHTTP is an H2 transport — h2/xhttp exist only under `mux`; `vless`
    // alone must still compile this suite (no-default-features resolution).
    #[cfg(feature = "mux")]
    #[tokio::test]
    async fn vless_over_xhttp_roundtrip() {
        use bytes::Bytes;
        use meow_transport::xhttp::{XhttpConfig, XhttpLayer};

        let (echo_addr, _echo) = start_tcp_echo_server().await;

        // Start an H2 server that terminates the XHTTP tunnel and unwraps the inner VLESS stream.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_h2_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut connection) =
                        h2::server::Builder::new().handshake::<_, Bytes>(tcp).await
                    else {
                        return;
                    };

                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        // Send 200 OK response header lazily to start the bidirectional stream
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let mut send_body = respond.send_response(response, false).unwrap();
                        let mut recv_body = request.into_body();

                        // Bridge the h2 stream into AsyncRead + AsyncWrite
                        let (client_r, mut client_w) = tokio::io::duplex(64 * 1024);
                        let (mut server_r, server_w) = tokio::io::duplex(64 * 1024);

                        // Forward recv_body -> server_w
                        tokio::spawn(async move {
                            let mut server_w = server_w;
                            while let Some(Ok(chunk)) = recv_body.data().await {
                                let _ = recv_body.flow_control().release_capacity(chunk.len());
                                if server_w.write_all(&chunk).await.is_err() {
                                    break;
                                }
                            }
                        });

                        // Forward client_r -> send_body
                        tokio::spawn(async move {
                            let mut client_r = client_r;
                            let mut buf = vec![0u8; 8192];
                            loop {
                                match client_r.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        send_body.reserve_capacity(n);
                                        if send_body
                                            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                        });

                        // Run mock VLESS server over server_r + client_w
                        tokio::spawn(async move {
                            let Ok((uuid, cmd, target_addr)) =
                                read_vless_header(&mut server_r).await
                            else {
                                return;
                            };
                            if uuid != TEST_UUID {
                                return;
                            }
                            if client_w.write_all(&[0x00, 0x00]).await.is_err() {
                                return;
                            }
                            if cmd == 0x01 {
                                if let Ok(mut target) = TcpStream::connect(target_addr).await {
                                    let (mut tr, mut tw) = target.split();
                                    let _ = tokio::join!(
                                        tokio::io::copy(&mut server_r, &mut tw),
                                        tokio::io::copy(&mut tr, &mut client_w)
                                    );
                                }
                            }
                        });
                    }
                });
            }
        });

        // Build VlessAdapter with XhttpLayer in TransportChain
        let mut chain = TransportChain::empty();
        let xhttp_cfg = XhttpConfig {
            path: "/xhttp-vless".into(),
            hosts: vec!["xhttp.test.com".into()],
            ..Default::default()
        };
        chain.push(Box::new(XhttpLayer::new(xhttp_cfg)));

        let adapter = VlessAdapter::new(
            "test-vless-xhttp",
            "127.0.0.1",
            vless_h2_addr.port(),
            TEST_UUID,
            None,
            false,
            chain,
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
            .await
            .expect("dial_tcp timed out")
            .expect("dial_tcp failed");

        let payload = b"hello vless over xhttp";
        conn.write_all(payload).await.expect("write payload failed");
        conn.flush().await.expect("flush failed");

        let mut buf = vec![0u8; payload.len()];
        conn.read_exact(&mut buf).await.expect("read echo failed");
        assert_eq!(&buf, payload, "round-trip data must match");
    }
}

// ─── Issue #570: relay-chain final hop (connect_over) ───────────────────────

#[cfg(feature = "vless")]
mod connect_over_tests {
    use super::vless_tests::{start_mock_vless_server, start_tcp_echo_server, TEST_UUID, TIMEOUT};
    use meow_common::{
        AdapterType, DelayHistory, Metadata, Network, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
        ProxyPacketConn, Result,
    };
    use meow_proxy::dialer::DirectDialer;
    use meow_proxy::{DirectAdapter, RelayGroup, TransportChain, VlessAdapter};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    /// Minimal `Proxy` wrapper so leaf adapters can sit in a `RelayGroup` —
    /// production wiring wraps adapters via meow-config's `WrappedProxy`,
    /// which meow-proxy tests cannot reach (crate direction).
    struct LeafProxy<A: ProxyAdapter>(A);

    #[async_trait::async_trait]
    impl<A: ProxyAdapter> ProxyAdapter for LeafProxy<A> {
        fn name(&self) -> &str {
            self.0.name()
        }
        fn adapter_type(&self) -> AdapterType {
            self.0.adapter_type()
        }
        fn addr(&self) -> &str {
            self.0.addr()
        }
        fn support_udp(&self) -> bool {
            self.0.support_udp()
        }
        async fn dial_tcp(&self, m: &Metadata) -> Result<Box<dyn ProxyConn>> {
            self.0.dial_tcp(m).await
        }
        async fn dial_udp(&self, m: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            self.0.dial_udp(m).await
        }
        async fn connect_over(
            &self,
            s: Box<dyn ProxyConn>,
            m: &Metadata,
        ) -> Result<Box<dyn ProxyConn>> {
            self.0.connect_over(s, m).await
        }
        fn health(&self) -> &ProxyHealth {
            self.0.health()
        }
    }

    impl<A: ProxyAdapter> Proxy for LeafProxy<A> {
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

    fn vless_adapter(server_port: u16, uuid: [u8; 16]) -> VlessAdapter {
        VlessAdapter::new(
            "test-vless-connect-over",
            "127.0.0.1",
            server_port,
            uuid,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        )
    }

    fn echo_metadata(echo_port: u16) -> Metadata {
        Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_port,
            ..Default::default()
        }
    }

    /// `connect_over` must run the adapter's full post-connect pipeline —
    /// transport chain + VLESS header — over the caller-supplied stream.
    /// The mock asserts the UUID and relays to the echo target, so a skipped
    /// or garbled handshake fails immediately.
    #[tokio::test]
    async fn vless_connect_over_runs_vless_handshake() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;
        // Port 1 is dead: a `connect_over` that ignored the supplied stream
        // and re-dialed its own server would fail — the ONLY path to the
        // mock is through `upstream`.
        let adapter = vless_adapter(1, TEST_UUID);

        // The relay chain's hop-0 leg: a plain TCP stream already connected
        // to the VLESS server.
        let upstream: Box<dyn ProxyConn> = Box::new(
            TcpStream::connect(vless_addr)
                .await
                .expect("upstream connect"),
        );

        let mut conn = timeout(
            TIMEOUT,
            adapter.connect_over(upstream, &echo_metadata(echo_addr.port())),
        )
        .await
        .expect("connect_over timed out")
        .expect("connect_over failed");

        timeout(TIMEOUT, async {
            let payload = b"vless over relay-supplied stream";
            conn.write_all(payload).await.expect("write failed");
            conn.flush().await.expect("flush failed");
            let mut buf = vec![0u8; payload.len()];
            conn.read_exact(&mut buf).await.expect("read_exact failed");
            assert_eq!(&buf, payload, "echo mismatch through connect_over");
        })
        .await
        .expect("connect_over echo timed out");
    }

    /// `connect_over` must apply the adapter's configured transport chain —
    /// not just the VLESS header — over the supplied stream. The mock
    /// terminates TLS (self-signed, skipped verify client-side) and only
    /// then parses VLESS, so a plaintext header fails the TLS handshake
    /// outright.
    #[tokio::test]
    async fn vless_connect_over_applies_tls_transport() {
        use meow_transport::tls::{TlsConfig, TlsLayer};

        let (echo_addr, _echo) = start_tcp_echo_server().await;

        // Mock VLESS server behind TLS: accept → rustls handshake →
        // VLESS header → relay to echo.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    ck.cert.der().to_vec(),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
                ),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_tls_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        eprintln!("mock vless+tls: TLS accept error — handshake missing?");
                        return;
                    };
                    let Ok((uuid, cmd, target_addr)) =
                        super::vless_tests::read_vless_header(&mut tls).await
                    else {
                        eprintln!("mock vless+tls: header parse error");
                        return;
                    };
                    if uuid != TEST_UUID {
                        return;
                    }
                    if tls.write_all(&[0x00, 0x00]).await.is_err() {
                        return;
                    }
                    if cmd == 0x01 {
                        if let Ok(mut target) = TcpStream::connect(target_addr).await {
                            let _ = tokio::io::copy_bidirectional(&mut tls, &mut target).await;
                        }
                    }
                });
            }
        });

        let mut tls_cfg = TlsConfig::new("localhost");
        tls_cfg.skip_cert_verify = true;
        let mut chain = TransportChain::empty();
        chain.push(Box::new(TlsLayer::new(&tls_cfg).expect("tls layer")));
        // Dead port 1: only the supplied stream can reach the mock.
        let adapter = VlessAdapter::new(
            "test-vless-tls-connect-over",
            "127.0.0.1",
            1,
            TEST_UUID,
            None,
            false,
            chain,
            Arc::new(DirectDialer),
        );

        let upstream: Box<dyn ProxyConn> = Box::new(
            TcpStream::connect(vless_tls_addr)
                .await
                .expect("upstream connect"),
        );
        let mut conn = timeout(
            TIMEOUT,
            adapter.connect_over(upstream, &echo_metadata(echo_addr.port())),
        )
        .await
        .expect("connect_over timed out")
        .expect("connect_over must run TLS over the supplied stream");

        timeout(TIMEOUT, async {
            let payload = b"vless+tls over relay-supplied stream";
            conn.write_all(payload).await.expect("write failed");
            conn.flush().await.expect("flush failed");
            let mut buf = vec![0u8; payload.len()];
            conn.read_exact(&mut buf).await.expect("read_exact failed");
            assert_eq!(&buf, payload, "echo mismatch through TLS connect_over");
        })
        .await
        .expect("TLS connect_over echo timed out");
    }

    /// Real three-hop chain `[vless₁ → direct → vless₂]`: hop 0 is itself a
    /// full adapter (not direct), the middle hop is a passthrough, and the
    /// final hop `connect_over`s onto the compounded stream. Exercises
    /// metadata_for_next_hop skipping the addressless middle hop — hop 0's
    /// VLESS request must target vless₂'s server, not `direct`'s "".
    #[tokio::test]
    async fn relay_group_vless_direct_vless_roundtrip() {
        // vless₂ uses a distinct UUID: if hop 0 misroutes its VLESS request
        // to a wrong-but-VLESS-speaking server (e.g. vless₁'s own listener),
        // the UUID mismatch closes the connection instead of silently
        // passing through an unintended path.
        const UUID2: [u8; 16] = [0xa5; 16];
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless1_addr, _v1) = start_mock_vless_server(TEST_UUID).await;
        let (vless2_addr, _v2) = start_mock_vless_server(UUID2).await;

        let relay = RelayGroup::new(
            "test-relay-3hop",
            vec![
                Arc::new(LeafProxy(vless_adapter(vless1_addr.port(), TEST_UUID))) as Arc<dyn Proxy>,
                Arc::new(LeafProxy(DirectAdapter::new())) as Arc<dyn Proxy>,
                Arc::new(LeafProxy(vless_adapter(vless2_addr.port(), UUID2))) as Arc<dyn Proxy>,
            ],
        );

        let mut conn = timeout(TIMEOUT, relay.dial_tcp(&echo_metadata(echo_addr.port())))
            .await
            .expect("relay dial_tcp timed out")
            .expect("relay dial_tcp failed");

        timeout(TIMEOUT, async {
            let payload = b"vless-direct-vless three-hop roundtrip";
            conn.write_all(payload).await.expect("write failed");
            conn.flush().await.expect("flush failed");
            let mut buf = vec![0u8; payload.len()];
            conn.read_exact(&mut buf).await.expect("read_exact failed");
            assert_eq!(&buf, payload, "three-hop relay echo mismatch");
        })
        .await
        .expect("three-hop echo timed out");
    }

    /// Full `RelayGroup [direct → vless]` end-to-end: hop 0 `dial_tcp`s to
    /// the VLESS server, hop 1 `connect_over`s onto that stream and speaks
    /// VLESS to the real target.
    #[tokio::test]
    async fn relay_group_direct_then_vless_roundtrip() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let relay = RelayGroup::new(
            "test-relay",
            vec![
                Arc::new(LeafProxy(DirectAdapter::new())) as Arc<dyn Proxy>,
                Arc::new(LeafProxy(vless_adapter(vless_addr.port(), TEST_UUID))) as Arc<dyn Proxy>,
            ],
        );

        let mut conn = timeout(TIMEOUT, relay.dial_tcp(&echo_metadata(echo_addr.port())))
            .await
            .expect("relay dial_tcp timed out")
            .expect("relay dial_tcp failed");

        let payload = b"direct then vless relay roundtrip";
        conn.write_all(payload).await.expect("write failed");
        conn.flush().await.expect("flush failed");
        let mut buf = vec![0u8; payload.len()];
        conn.read_exact(&mut buf).await.expect("read_exact failed");
        assert_eq!(&buf, payload, "relay echo mismatch");
    }
}

// ─── Vision UDP via Mux.Cool — spec item 1 ───────────────────────────────────
//
// sing-box ≥1.12 (its vendored sing-vmess `vless.Service`) verifies
// `request.Flow == account.Flow` on EVERY command, so a vision user's
// bare `Cmd::Udp` request — empty addon — is rejected as a flow
// mismatch, while a `Cmd::Udp` request carrying the addon is rejected by
// all three upstream servers.  Upstream clients therefore route vision
// UDP over a CommandMux session: the physical request is `cmd=0x03`
// with the `xtls-rprx-vision` addon and the association is a
// `network=0x02` Mux.Cool substream.  The strict mock below enforces
// exactly that flow check and serves the mux loopback.
#[cfg(all(feature = "vless-vision", feature = "mux"))]
mod vision_udp_mux {
    use super::vless_tests::{TEST_UUID, TIMEOUT};
    use meow_common::{Metadata, Network, ProxyAdapter, ProxyPacketConn};
    use meow_proxy::dialer::DirectDialer;
    use meow_proxy::{TransportChain, VlessAdapter, VlessFlow};
    use std::collections::VecDeque;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    const XRV: &str = "xtls-rprx-vision";

    /// Wire observations the mock server records — asserted after the
    /// client exchange (request cmd + flow, Mux.Cool New-frame network).
    type Log = Arc<Mutex<Vec<String>>>;

    fn push(log: &Log, line: String) {
        log.lock().unwrap().push(line);
    }

    /// Buffered stream reader.  A Vision frame's *content* and the bytes
    /// after a bare request belong to the mux/datagram layer — `unread`
    /// pushes them back so one reader serves both layers.
    struct Wire {
        tcp: TcpStream,
        pending: VecDeque<u8>,
    }

    impl Wire {
        fn new(tcp: TcpStream) -> Self {
            Self {
                tcp,
                pending: VecDeque::new(),
            }
        }

        async fn read_n(&mut self, n: usize) -> io::Result<Vec<u8>> {
            while self.pending.len() < n {
                let mut buf = [0u8; 8192];
                let k = self.tcp.read(&mut buf).await?;
                if k == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "wire: eof"));
                }
                self.pending.extend(&buf[..k]);
            }
            Ok(self.pending.drain(..n).collect())
        }

        async fn read_u16(&mut self) -> io::Result<u16> {
            let b = self.read_n(2).await?;
            Ok(u16::from_be_bytes([b[0], b[1]]))
        }

        fn unread(&mut self, bytes: &[u8]) {
            self.pending.reserve(bytes.len());
            for &b in bytes.iter().rev() {
                self.pending.push_front(b);
            }
        }
    }

    /// The request fields the strict mock needs — `read_vless_header`
    /// discards the addon, which carries the flow the check verifies.
    struct Request {
        uuid: [u8; 16],
        flow: Option<String>,
        cmd: u8,
    }

    async fn read_vless_request(w: &mut Wire) -> io::Result<Request> {
        let version = w.read_n(1).await?;
        if version[0] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("strict vless: version {:#04x}", version[0]),
            ));
        }
        let uuid: [u8; 16] = w
            .read_n(16)
            .await?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "uuid"))?;
        let addon_len = w.read_n(1).await?[0] as usize;
        let addon = w.read_n(addon_len).await?;
        // Addon is protobuf-lite: field 1 (`flow`) is `[0x0A, len, utf8]`.
        let flow = if addon.len() >= 2 && addon[0] == 0x0A {
            let l = addon[1] as usize;
            (addon.len() == 2 + l).then(|| String::from_utf8_lossy(&addon[2..]).into_owned())
        } else {
            None
        };
        let cmd = w.read_n(1).await?[0];
        if cmd != 0x03 {
            // TCP/UDP requests carry port + address — drain them.
            let _port = w.read_n(2).await?;
            match w.read_n(1).await?[0] {
                0x01 => {
                    w.read_n(4).await?;
                }
                0x02 => {
                    let l = w.read_n(1).await?[0] as usize;
                    w.read_n(l).await?;
                }
                0x03 => {
                    w.read_n(16).await?;
                }
                t => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("strict vless: addr_type {t:#04x}"),
                    ))
                }
            }
        }
        Ok(Request { uuid, flow, cmd })
    }

    /// Read the client's first Vision padding frame (uuid + command +
    /// content + padding) and push its content back — after the END
    /// command the rest of the stream passes through raw.
    async fn unwrap_vision_frame(w: &mut Wire) -> io::Result<()> {
        let uuid = w.read_n(16).await?;
        if uuid != TEST_UUID {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "strict vless: vision frame uuid mismatch",
            ));
        }
        let _command = w.read_n(1).await?[0];
        let content_len = w.read_u16().await? as usize;
        let padding_len = w.read_u16().await? as usize;
        let content = w.read_n(content_len).await?;
        let _padding = w.read_n(padding_len).await?;
        w.unread(&content);
        Ok(())
    }

    /// The server side of a Vision conn: the VLESS response header is raw
    /// (`VlessConn` inside `VisionConn` parses it before the Vision layer
    /// unwraps frames), then one padding frame — uuid + END + empty
    /// content — after which both directions pass through raw.
    async fn write_vision_response(w: &mut Wire) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(23);
        bytes.extend_from_slice(&[0x00, 0x00]);
        bytes.extend_from_slice(&TEST_UUID);
        bytes.push(0x01); // END — content is not TLS data
        bytes.extend_from_slice(&0u16.to_be_bytes()); // content_len
        bytes.extend_from_slice(&0u16.to_be_bytes()); // padding_len
        w.tcp.write_all(&bytes).await
    }

    /// Serve Mux.Cool frames: record each UDP New frame and echo every
    /// Keep+Data datagram back with its declared destination, so the
    /// client's `read_packet` reports the target as source.
    async fn mux_loopback(w: &mut Wire, log: &Log) -> io::Result<()> {
        loop {
            let meta_len = w.read_u16().await? as usize;
            let meta = w.read_n(meta_len).await?;
            if meta.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "strict vless: meta < 4",
                ));
            }
            let sid = u16::from_be_bytes([meta[0], meta[1]]);
            let status = meta[2];
            let option = meta[3];
            let dest_meta = &meta[4..]; // [network][port][atype][addr] when present
            match status {
                0x01 => {
                    // New frame — the spec requires network=0x02 (UDP).
                    if dest_meta.first() != Some(&0x02) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("strict vless: New frame sid={sid} not UDP"),
                        ));
                    }
                    push(log, format!("new udp sid={sid}"));
                }
                0x02 if option & 0x01 != 0 => {
                    // Keep+Data — echo the datagram with the same dest.
                    let dlen = w.read_u16().await? as usize;
                    let data = w.read_n(dlen).await?;
                    let mut frame = Vec::with_capacity(6 + dest_meta.len() + data.len());
                    frame.extend_from_slice(&((4 + dest_meta.len()) as u16).to_be_bytes());
                    frame.extend_from_slice(&meta[..4]);
                    frame.extend_from_slice(dest_meta);
                    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    frame.extend_from_slice(&data);
                    w.tcp.write_all(&frame).await?;
                }
                // Keep without data / End / KeepAlive — nothing to do.
                0x02..=0x04 => {}
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("strict vless: frame status {other:#04x}"),
                    ))
                }
            }
        }
    }

    async fn serve_conn(
        tcp: TcpStream,
        user_flow: Option<&'static str>,
        log: &Log,
    ) -> io::Result<()> {
        let mut w = Wire::new(tcp);
        let req = read_vless_request(&mut w).await?;
        if req.uuid != TEST_UUID {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "strict vless: uuid mismatch",
            ));
        }
        // sing-box ≥1.12 strictness: the addon flow must equal the
        // account's for every command — close without a response on a
        // mismatch, exactly what the bare-UDP vision request hit.
        if req.flow.as_deref() != user_flow {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "strict vless: flow mismatch",
            ));
        }
        push(
            log,
            format!("request cmd={:#04x} flow={:?}", req.cmd, req.flow),
        );
        match req.cmd {
            // Bare UDP — `[u16 len][datagram]` echo after the response.
            0x02 => {
                w.tcp.write_all(&[0x00, 0x00]).await?;
                loop {
                    let n = w.read_u16().await? as usize;
                    let data = w.read_n(n).await?;
                    w.tcp.write_all(&(data.len() as u16).to_be_bytes()).await?;
                    w.tcp.write_all(&data).await?;
                }
            }
            // CommandMux — vision accounts see the request wrapped in the
            // client's first Vision frame and answer with their own.
            0x03 => {
                if user_flow.is_some() {
                    unwrap_vision_frame(&mut w).await?;
                    write_vision_response(&mut w).await?;
                } else {
                    w.tcp.write_all(&[0x00, 0x00]).await?;
                }
                mux_loopback(&mut w, log).await
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("strict vless: cmd {other:#04x}"),
            )),
        }
    }

    /// Mock VLESS server enforcing `request.flow == user_flow` the way
    /// sing-box ≥1.12 does — a flow mismatch closes without a response.
    async fn start_strict_vless_server(
        user_flow: Option<&'static str>,
    ) -> (SocketAddr, Log, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let server_log = Arc::clone(&log);
        let handle = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let log = Arc::clone(&server_log);
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(tcp, user_flow, &log).await {
                        eprintln!("strict vless: {e}");
                    }
                });
            }
        });
        (addr, log, handle)
    }

    fn vision_adapter(port: u16) -> VlessAdapter {
        VlessAdapter::new(
            "vision-udp",
            "127.0.0.1",
            port,
            TEST_UUID,
            Some(VlessFlow::XtlsRprxVision),
            true, // udp
            TransportChain::empty(),
            Arc::new(DirectDialer),
        )
    }

    fn udp_metadata(target: SocketAddr) -> Metadata {
        Metadata {
            network: Network::Udp,
            host: target.ip().to_string().into(),
            dst_ip: Some(target.ip()),
            dst_port: target.port(),
            ..Default::default()
        }
    }

    /// Spec item 1: vision `dial_udp` must emit a CommandMux request
    /// (cmd=0x03) carrying the xtls-rprx-vision addon, open a
    /// `network=0x02` Mux.Cool substream, and relay the datagram — the
    /// strict server rejects every other shape a flow user can emit.
    #[tokio::test]
    async fn vision_udp_rides_muxcool_session() {
        let (addr, log, _server) = start_strict_vless_server(Some(XRV)).await;
        let adapter = vision_adapter(addr.port());
        assert!(
            adapter.support_udp(),
            "mux + vless-vision compiled in → vision UDP advertised"
        );

        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let conn = timeout(TIMEOUT, adapter.dial_udp(&udp_metadata(target)))
            .await
            .expect("vision udp: dial_udp timed out")
            .expect("vision udp: dial_udp failed");

        let payload = b"vision-udp-dns-query";
        conn.write_packet(payload, &target)
            .await
            .expect("vision udp: write_packet failed");
        let mut buf = [0u8; 512];
        let (n, src) = timeout(TIMEOUT, conn.read_packet(&mut buf))
            .await
            .expect("vision udp: read_packet timed out")
            .expect("vision udp: read_packet failed");
        assert_eq!(&buf[..n], payload, "vision udp: datagram echo mismatch");
        assert_eq!(src, target, "vision udp: datagram source");

        // The round-trip already proves the strict flow check passed; the
        // recorded request pins the exact wire shape (cmd=0x03 + addon).
        let seen = log.lock().unwrap();
        assert!(
            seen.iter()
                .any(|l| *l == "request cmd=0x03 flow=Some(\"xtls-rprx-vision\")"),
            "expected CommandMux request with xtls-rprx-vision addon, log: {seen:?}"
        );
        assert!(
            seen.iter().any(|l| l.starts_with("new udp")),
            "expected a network=0x02 Mux.Cool New frame, log: {seen:?}"
        );
    }

    /// A domain UDP target cannot ride Mux.Cool — its Keep frame stamps
    /// a `SocketAddr` per datagram — so `dial_udp` falls back to the bare
    /// `Cmd::Udp` request and warns once.
    #[tokio::test]
    async fn vision_udp_domain_target_falls_back_and_warns_once() {
        // Lenient listener (a no-flow account): accepts the bare request
        // the fallback emits and echoes datagrams.
        let (addr, log, _server) = start_strict_vless_server(None).await;
        let adapter = vision_adapter(addr.port());
        let meta = Metadata {
            network: Network::Udp,
            host: "dns.example".into(),
            dst_port: 5353,
            dst_ip: None,
            ..Default::default()
        };

        let logs = LogSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let mut conns: Vec<Box<dyn ProxyPacketConn>> = Vec::new();
        for _ in 0..2 {
            conns.push(
                timeout(TIMEOUT, adapter.dial_udp(&meta))
                    .await
                    .expect("domain fallback: dial_udp timed out")
                    .expect("domain fallback: dial_udp failed"),
            );
        }
        drop(guard);

        // The bare conns actually relay on a tolerant listener — one echo
        // round-trip on each also forces the server to have processed
        // both requests before the log assert below.
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);
        for conn in &conns {
            let payload = b"domain-fallback";
            conn.write_packet(payload, &target)
                .await
                .expect("domain fallback: write_packet failed");
            let mut buf = [0u8; 512];
            let (n, _) = timeout(TIMEOUT, conn.read_packet(&mut buf))
                .await
                .expect("domain fallback: read_packet timed out")
                .expect("domain fallback: read_packet failed");
            assert_eq!(&buf[..n], payload);
        }

        // Both associations reached the wire as bare `Cmd::Udp` requests
        // with no flow addon — the fallback Mux.Cool declined.
        {
            let seen = log.lock().unwrap();
            let bare = seen
                .iter()
                .filter(|l| *l == "request cmd=0x02 flow=None")
                .count();
            assert_eq!(bare, 2, "expected two bare UDP requests, log: {seen:?}");
        }

        // The strict-server rejection is warned exactly once per adapter.
        let logs = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
        let warns = logs.matches("fell back to a bare Cmd::Udp request").count();
        assert_eq!(warns, 1, "warn-once violated, logs:\n{logs}");
    }

    /// Regression: a non-vision adapter keeps the plain `Cmd::Udp` path —
    /// no flow addon, no CommandMux — and relays as before.
    #[tokio::test]
    async fn non_vision_udp_stays_bare_cmd_udp() {
        let (addr, log, _server) = start_strict_vless_server(None).await;
        let adapter = VlessAdapter::new(
            "plain-udp",
            "127.0.0.1",
            addr.port(),
            TEST_UUID,
            None,
            true, // udp
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);
        let conn = timeout(TIMEOUT, adapter.dial_udp(&udp_metadata(target)))
            .await
            .expect("plain udp: dial_udp timed out")
            .expect("plain udp: dial_udp failed");
        let payload = b"plain-udp-query";
        conn.write_packet(payload, &target)
            .await
            .expect("plain udp: write_packet failed");
        let mut buf = [0u8; 512];
        let (n, _) = timeout(TIMEOUT, conn.read_packet(&mut buf))
            .await
            .expect("plain udp: read_packet timed out")
            .expect("plain udp: read_packet failed");
        assert_eq!(&buf[..n], payload, "plain udp: echo mismatch");

        let seen = log.lock().unwrap();
        assert!(
            seen.iter().any(|l| *l == "request cmd=0x02 flow=None"),
            "non-vision UDP must stay a bare Cmd::Udp request, log: {seen:?}"
        );
    }

    /// Test-side capture of the client's `tracing` output, mirrored from
    /// the xray-server integration tests' `LogSink`.
    #[derive(Clone, Default)]
    struct LogSink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }
}
