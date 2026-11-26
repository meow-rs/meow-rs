//! In-process integration tests for the VLESS Vision server inbound.
#![cfg(feature = "listener-vless")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use meow_common::{Metadata, Network, ProxyAdapter};
use meow_dns::Resolver;
use meow_listener::{
    VlessFallbackLimit, VlessListener, VlessListenerSpec, VlessRealitySpec, VlessSecuritySpec,
    VlessUserSpec,
};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::{TransportChain, VlessAdapter, VlessFlow};
use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer, TlsVersion};
use meow_transport::Transport;
use meow_tunnel::Tunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

const T: Duration = Duration::from_secs(8);
const ALICE: [u8; 16] = [0x11; 16];
const BOB: [u8; 16] = [0x22; 16];
const WRONG: [u8; 16] = [0x33; 16];
const REALITY_PRIVATE: [u8; 32] = [0x42; 32];
const SHORT_ID: [u8; 8] = [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0];

fn metadata(addr: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Tcp,
        host: addr.ip().to_string().into(),
        dst_port: addr.port(),
        ..Default::default()
    }
}

fn tunnel_with_rules(rule_lines: &[&str]) -> Tunnel {
    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        false,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    let ctx = meow_rules::parser::ParserContext::empty();
    let mut rules: Vec<Box<dyn meow_common::Rule>> = rule_lines
        .iter()
        .map(|line| meow_rules::parse_rule(line, &ctx).unwrap())
        .collect();
    rules.push(Box::new(meow_rules::final_rule::FinalRule::new("DIRECT")));
    tunnel.update_rules(rules);
    tunnel
}

// `copy_bidirectional` cannot copy a stream onto itself. This separate
// implementation is small and deliberately bounded by peer EOF/error.
async fn echo_conn(mut stream: TcpStream) {
    let (mut rd, mut wr) = stream.split();
    let _ = tokio::io::copy(&mut rd, &mut wr).await;
}

async fn start_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(echo_conn(stream));
        }
    });
    addr
}

fn tls_cert() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

fn tls_spec(cert: &str, key: &str, users: Vec<(&str, [u8; 16])>) -> VlessListenerSpec {
    VlessListenerSpec {
        users: users
            .into_iter()
            .map(|(username, uuid)| VlessUserSpec {
                username: username.into(),
                uuid,
            })
            .collect(),
        security: VlessSecuritySpec::StandardTls {
            certificate: cert.into(),
            private_key: key.into(),
            alpn: vec![],
        },
        udp: true,
    }
}

fn reality_spec(dest: String, users: Vec<(&str, [u8; 16])>) -> VlessListenerSpec {
    VlessListenerSpec {
        users: users
            .into_iter()
            .map(|(username, uuid)| VlessUserSpec {
                username: username.into(),
                uuid,
            })
            .collect(),
        security: VlessSecuritySpec::Reality(VlessRealitySpec {
            dest,
            private_key: REALITY_PRIVATE,
            short_ids: vec![SHORT_ID],
            server_names: vec!["localhost".into()],
            max_time_difference_us: 120_000_000,
            limit_fallback_upload: VlessFallbackLimit::default(),
            limit_fallback_download: VlessFallbackLimit::default(),
        }),
        udp: true,
    }
}

async fn start_listener(
    spec: VlessListenerSpec,
    tunnel: Tunnel,
    name: &str,
) -> (u16, Arc<VlessListener>, tokio::task::JoinHandle<()>) {
    let listener = Arc::new(VlessListener::new(tunnel, name.into(), spec).unwrap());
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = socket.local_addr().unwrap();
    listener.note_bound_endpoint(bound);
    let task_listener = Arc::clone(&listener);
    let task = tokio::spawn(async move {
        let _ = task_listener.run_on(socket).await;
    });
    (bound.port(), listener, task)
}

fn vision_adapter(
    port: u16,
    uuid: [u8; 16],
    tls: &TlsConfig,
    flow: Option<VlessFlow>,
) -> VlessAdapter {
    let mut chain = TransportChain::empty();
    chain.push(Box::new(TlsLayer::new(tls).expect("TLS layer")));
    VlessAdapter::new(
        "vless-test-client",
        "127.0.0.1",
        port,
        uuid,
        flow,
        true,
        chain,
        Arc::new(DirectDialer),
    )
}

fn tls_client_config() -> TlsConfig {
    TlsConfig {
        skip_cert_verify: true,
        ..TlsConfig::new("localhost")
    }
}

fn vision_tls_adapter(port: u16, uuid: [u8; 16]) -> VlessAdapter {
    vision_adapter(
        port,
        uuid,
        &tls_client_config(),
        Some(VlessFlow::XtlsRprxVision),
    )
}

fn reality_public_key() -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(REALITY_PRIVATE);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

fn vision_reality_adapter(port: u16, uuid: [u8; 16]) -> VlessAdapter {
    let tls = TlsConfig {
        reality: Some(RealityConfig {
            public_key: reality_public_key(),
            short_id: SHORT_ID,
            support_x25519_mlkem768: false,
            protocol_clock: None,
        }),
        ..TlsConfig::new("localhost")
    };
    vision_adapter(port, uuid, &tls, Some(VlessFlow::XtlsRprxVision))
}

async fn echo_roundtrip(
    conn: &mut dyn meow_common::ProxyConn,
    payload: &[u8],
) -> Result<(), String> {
    timeout(T, async {
        conn.write_all(payload)
            .await
            .map_err(|e| format!("write: {e}"))?;
        conn.flush().await.map_err(|e| format!("flush: {e}"))?;
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got)
            .await
            .map_err(|e| format!("read: {e}"))?;
        (got == payload)
            .then_some(())
            .ok_or_else(|| "echo corruption".to_string())
    })
    .await
    .map_err(|_| "timeout".to_string())?
}

async fn adapter_echo(
    adapter: &VlessAdapter,
    target: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let mut conn = timeout(T, adapter.dial_tcp(&metadata(target)))
        .await
        .map_err(|_| "dial timeout".to_string())?
        .map_err(|e| format!("dial: {e}"))?;
    echo_roundtrip(&mut *conn, payload).await
}

fn pkcs8_key(key: &rcgen::KeyPair) -> rustls::pki_types::PrivateKeyDer<'static> {
    rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key.serialize_der(),
    ))
}

async fn start_tls13_echo() -> (SocketAddr, rustls::pki_types::CertificateDer<'static>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], pkcs8_key(&ck.key_pair))
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let (mut rd, mut wr) = tokio::io::split(tls);
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                }
            });
        }
    });
    (addr, cert)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_vision_end_to_end_direct_and_in_user_routing() {
    let echo = start_tcp_echo().await;
    let (tls_target, target_cert) = start_tls13_echo().await;
    let (cert, key) = tls_cert();
    // Alice's authenticated username must reach rule matching; Bob remains
    // DIRECT. If `in_user` is dropped, Alice succeeds and this test fails.
    let tunnel = tunnel_with_rules(&["IN-USER,alice,REJECT"]);
    let spec = tls_spec(&cert, &key, vec![("alice", ALICE), ("bob", BOB)]);
    let (port, listener, _task) = start_listener(spec, tunnel, "vless-tls-it").await;

    let bob = vision_tls_adapter(port, BOB);
    let outer = timeout(T, bob.dial_tcp(&metadata(tls_target)))
        .await
        .expect("dial timeout")
        .expect("bob dial");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(target_cert).unwrap();
    let inner_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(inner_cfg));
    let mut inner = timeout(
        T,
        connector.connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            outer,
        ),
    )
    .await
    .expect("inner TLS timeout")
    .expect("inner TLS through Vision");
    assert_eq!(
        inner.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let payload = vec![0x5au8; 256 * 1024 + 17];
    inner.write_all(&payload).await.unwrap();
    inner.flush().await.unwrap();
    let mut got = vec![0u8; payload.len()];
    timeout(T, inner.read_exact(&mut got))
        .await
        .expect("inner echo timeout")
        .expect("inner echo read");
    assert_eq!(got, payload);
    // DIRECT is armed only after the final padding frame has completely
    // drained; the next downlink write is the first one that can actually
    // travel raw. Exchange one more small record before closing.
    inner.write_all(b"post-direct-probe").await.unwrap();
    inner.flush().await.unwrap();
    let mut probe = vec![0u8; b"post-direct-probe".len()];
    timeout(T, inner.read_exact(&mut probe))
        .await
        .expect("post-DIRECT echo timeout")
        .expect("post-DIRECT echo read");
    assert_eq!(probe, b"post-direct-probe");
    drop(inner);

    for _ in 0..100 {
        if listener.vision_raw_switch_counts() == (1, 1) {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        listener.vision_raw_switch_counts(),
        (1, 1),
        "TLS 1.3 inner traffic must switch both Vision directions to raw DIRECT"
    );

    // Bob can still use a plaintext target; Alice is correctly authenticated
    // but her `IN-USER` rule rejects the routed flow.
    let bob_plain = vision_tls_adapter(port, BOB);
    adapter_echo(&bob_plain, echo, b"bob plaintext")
        .await
        .expect("bob plaintext echo");
    let alice = vision_tls_adapter(port, ALICE);
    assert!(
        adapter_echo(&alice, echo, b"alice must reject")
            .await
            .is_err(),
        "IN-USER,alice,REJECT must see the authenticated username"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_negative_auth_flow_plaintext_and_tls12() {
    let echo = start_tcp_echo().await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-tls-negative",
    )
    .await;

    let wrong_uuid = vision_tls_adapter(port, WRONG);
    assert!(adapter_echo(&wrong_uuid, echo, b"wrong uuid")
        .await
        .is_err());

    let no_flow = vision_adapter(port, ALICE, &tls_client_config(), None);
    assert!(adapter_echo(&no_flow, echo, b"missing vision flow")
        .await
        .is_err());

    // Plain bytes are not a TLS ClientHello: accept fails and the socket closes.
    let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    plain.write_all(b"plain probe").await.unwrap();
    // BoringSSL may emit a short TLS alert before closing. The negative
    // invariant is that the plaintext probe is never accepted or echoed.
    let mut reflected = vec![0u8; b"plain probe".len()];
    let plain_result = timeout(Duration::from_secs(2), plain.read_exact(&mut reflected)).await;
    assert!(matches!(plain_result, Ok(Err(_)) | Err(_)));

    // The standard acceptor is TLS 1.3-only; a TLS 1.2 offer must not complete.
    let mut tls12_cfg = tls_client_config();
    tls12_cfg.max_version = Some(TlsVersion::Tls12);
    let layer = TlsLayer::new(&tls12_cfg).unwrap();
    let raw: Box<dyn meow_transport::Stream> =
        Box::new(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    let tls12 = timeout(T, layer.connect(raw)).await;
    assert!(
        matches!(tls12, Ok(Err(_)) | Err(_)),
        "TLS 1.2 offer must not complete against the TLS 1.3-only acceptor"
    );

    // A valid authenticated Vision Mux request is decoded, then explicitly
    // closed in this TCP-only wave: no target dial, no response header and
    // no mux task/state left behind.
    let layer = TlsLayer::new(&tls_client_config()).unwrap();
    let raw: Box<dyn meow_transport::Stream> =
        Box::new(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    let mut mux = layer.connect(raw).await.unwrap();
    let flow = b"xtls-rprx-vision";
    let mut request = vec![0x00];
    request.extend_from_slice(&ALICE);
    request.extend_from_slice(&[18, 0x0a, 0x10]);
    request.extend_from_slice(flow);
    request.push(0x03);
    mux.write_all(&request).await.unwrap();
    mux.flush().await.unwrap();
    let mut response = [0u8; 2];
    let mux_read = timeout(Duration::from_secs(2), mux.read_exact(&mut response)).await;
    assert!(matches!(mux_read, Ok(Err(_)) | Err(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_vision_authenticated_echo() {
    let echo = start_tcp_echo().await;
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        reality_spec("127.0.0.1:9".into(), vec![("alice", ALICE)]),
        tunnel,
        "vless-reality-it",
    )
    .await;
    let adapter = vision_reality_adapter(port, ALICE);
    adapter_echo(&adapter, echo, b"reality vision echo")
        .await
        .expect("REALITY-authenticated Vision echo");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_ordinary_tls_is_transparently_cover_relayed() {
    let (cover, _cover_cert) = start_tls13_echo().await;
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        reality_spec(
            format!("127.0.0.1:{}", cover.port()),
            vec![("alice", ALICE)],
        ),
        tunnel,
        "vless-reality-cover-it",
    )
    .await;

    // A normal BoringTLS client has no REALITY auth payload. Classification
    // sends the preserved ClientHello prefix to the cover target, after which
    // the TLS handshake and application echo are byte-transparent.
    let layer = TlsLayer::new(&tls_client_config()).unwrap();
    let raw: Box<dyn meow_transport::Stream> =
        Box::new(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    let mut tls = timeout(T, layer.connect(raw))
        .await
        .expect("cover TLS timeout")
        .expect("cover TLS handshake");
    tls.write_all(b"ordinary tls through cover").await.unwrap();
    tls.flush().await.unwrap();
    let mut got = vec![0u8; b"ordinary tls through cover".len()];
    timeout(T, tls.read_exact(&mut got))
        .await
        .expect("cover echo timeout")
        .expect("cover echo read");
    assert_eq!(got, b"ordinary tls through cover");
}
