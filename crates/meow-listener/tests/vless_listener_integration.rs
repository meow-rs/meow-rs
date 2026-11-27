//! In-process integration tests for the VLESS Vision server inbound.
#![cfg(feature = "listener-vless")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use meow_common::{Metadata, Network, ProxyAdapter, ProxyPacketConn};
use meow_dns::Resolver;
use meow_listener::{
    VlessFallbackLimit, VlessListener, VlessListenerSpec, VlessRealitySpec, VlessSecuritySpec,
    VlessUserSpec,
};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::mux::xudp::{XudpDecoder, XudpFrame};
use meow_proxy::{TransportChain, VlessAdapter, VlessFlow};
use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer, TlsVersion};
use meow_transport::Transport;
use meow_tunnel::Tunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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

    // A valid authenticated Vision Mux request is accepted as an XUDP
    // association: no response header arrives before the first downlink
    // frame (xray sends it lazily with the first reply), so the read
    // below must TIME OUT still-open rather than end — the negative
    // invariant being that auth passed yet nothing is answered upfront.
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
    assert!(
        mux_read.is_err(),
        "an idle XUDP association stays open with no unsolicited response header: {mux_read:?}"
    );
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

// ─── XUDP (UDP-over-Vision) tests ───────────────────────────────────────────
//
// Two client shapes: the real meow VlessAdapter vision UDP path (production
// Mux.Cool client: bare New then Keep+Data per datagram) and a raw harness
// that hand-encodes vision/XUDP frames for multi-session, domain, negative
// and boundary shapes the client adapter cannot express.

async fn start_udp_echo(bind: &str) -> SocketAddr {
    let socket = UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            if socket.send_to(&buf[..n], src).await.is_err() {
                break;
            }
        }
    });
    addr
}

async fn start_udp_oversize_then_echo(bind: &str, reply_len: usize) -> SocketAddr {
    let socket = UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let oversize = vec![0x5au8; reply_len];
        let mut buf = vec![0u8; 65536];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            let reply = if &buf[..n] == b"trigger" {
                oversize.as_slice()
            } else {
                &buf[..n]
            };
            if socket.send_to(reply, src).await.is_err() {
                break;
            }
        }
    });
    addr
}

async fn start_udp_fixed_reply(bind: &str, reply_len: usize) -> SocketAddr {
    let socket = UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let reply = vec![0x5au8; reply_len];
        let mut buf = vec![0u8; 65536];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            let _ = n;
            if socket.send_to(&reply, src).await.is_err() {
                break;
            }
        }
    });
    addr
}

fn tunnel_with_hosts(rule_lines: &[&str], hosts: &[(&str, std::net::IpAddr)]) -> Tunnel {
    let mut trie = meow_trie::DomainTrie::new();
    for (name, ip) in hosts {
        trie.insert(name, vec![*ip].into());
    }
    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        trie,
        true,
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

// --- client-side frame crafting (xray/sing client wire shapes) --------------

fn xudp_frame(
    sid: u16,
    status: u8,
    option: u8,
    extra_meta: &[u8],
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut meta = Vec::new();
    meta.extend_from_slice(&sid.to_be_bytes());
    meta.push(status);
    meta.push(option);
    meta.extend_from_slice(extra_meta);
    let mut out = Vec::new();
    out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    out.extend_from_slice(&meta);
    if let Some(p) = payload {
        out.extend_from_slice(&(p.len() as u16).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn udp_target_meta(network: u8, port: u16, atype: u8, addr: &[u8]) -> Vec<u8> {
    let mut m = vec![network];
    m.extend_from_slice(&port.to_be_bytes());
    m.push(atype);
    m.extend_from_slice(addr);
    m
}

fn v4_target(ip: [u8; 4], port: u16) -> Vec<u8> {
    udp_target_meta(0x02, port, 0x01, &ip)
}

fn v6_target(ip: [u8; 16], port: u16) -> Vec<u8> {
    udp_target_meta(0x02, port, 0x03, &ip)
}

fn domain_target(name: &str, port: u16) -> Vec<u8> {
    let mut addr = vec![name.len() as u8];
    addr.extend_from_slice(name.as_bytes());
    udp_target_meta(0x02, port, 0x02, &addr)
}

fn new_data(sid: u16, target_meta: &[u8], payload: &[u8]) -> Vec<u8> {
    xudp_frame(sid, 0x01, 0x01, target_meta, Some(payload))
}

fn keep_data(sid: u16, target_meta: Option<&[u8]>, payload: &[u8]) -> Vec<u8> {
    xudp_frame(sid, 0x02, 0x01, target_meta.unwrap_or(&[]), Some(payload))
}

fn end_frame(sid: u16) -> Vec<u8> {
    xudp_frame(sid, 0x03, 0x00, &[], None)
}

// --- raw vision/XUDP client harness -----------------------------------------

/// Incremental downlink vision deframer: strips the response header, per-frame
/// headers/uuid/padding, and passes content bytes through; after an END/DIRECT
/// command the remainder of the stream is raw content.
struct VisionDeframer {
    resp_left: usize,
    uuid_left: usize,
    hdr: [u8; 5],
    hdr_filled: usize,
    cmd: u8,
    content_left: usize,
    pad_left: usize,
    raw: bool,
}

impl VisionDeframer {
    fn new() -> Self {
        Self {
            resp_left: 2,
            uuid_left: 16,
            hdr: [0; 5],
            hdr_filled: 0,
            cmd: 0,
            content_left: 0,
            pad_left: 0,
            raw: false,
        }
    }

    fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        while !input.is_empty() {
            if self.raw {
                out.extend_from_slice(input);
                return;
            }
            if self.resp_left > 0 {
                let take = self.resp_left.min(input.len());
                self.resp_left -= take;
                input = &input[take..];
                continue;
            }
            if self.uuid_left > 0 {
                let take = self.uuid_left.min(input.len());
                self.uuid_left -= take;
                input = &input[take..];
                continue;
            }
            if self.hdr_filled < 5 {
                let take = (5 - self.hdr_filled).min(input.len());
                self.hdr[self.hdr_filled..self.hdr_filled + take].copy_from_slice(&input[..take]);
                self.hdr_filled += take;
                input = &input[take..];
                if self.hdr_filled == 5 {
                    self.cmd = self.hdr[0];
                    self.content_left = u16::from_be_bytes([self.hdr[1], self.hdr[2]]) as usize;
                    self.pad_left = u16::from_be_bytes([self.hdr[3], self.hdr[4]]) as usize;
                }
                continue;
            }
            if self.content_left > 0 {
                let take = self.content_left.min(input.len());
                out.extend_from_slice(&input[..take]);
                self.content_left -= take;
                input = &input[take..];
                continue;
            }
            if self.pad_left > 0 {
                let take = self.pad_left.min(input.len());
                self.pad_left -= take;
                input = &input[take..];
                continue;
            }
            if self.cmd != 0 {
                self.raw = true;
            }
            self.hdr_filled = 0;
        }
    }
}

struct RawXudpClient {
    stream: Box<dyn meow_transport::Stream>,
    uuid: [u8; 16],
    first_sent: bool,
    deframer: VisionDeframer,
    decoder: XudpDecoder,
}

impl RawXudpClient {
    async fn connect(port: u16, uuid: [u8; 16]) -> Self {
        Self::connect_with_recv_buffer(port, uuid, None).await
    }

    async fn connect_with_recv_buffer(
        port: u16,
        uuid: [u8; 16],
        recv_buffer: Option<usize>,
    ) -> Self {
        let layer = TlsLayer::new(&tls_client_config()).unwrap();
        let raw: Box<dyn meow_transport::Stream> = if let Some(size) = recv_buffer {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .unwrap();
            socket.set_recv_buffer_size(size).unwrap();
            let peer = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port);
            socket.connect(&peer.into()).unwrap();
            socket.set_nonblocking(true).unwrap();
            let std_stream: std::net::TcpStream = socket.into();
            Box::new(TcpStream::from_std(std_stream).unwrap())
        } else {
            Box::new(TcpStream::connect(("127.0.0.1", port)).await.unwrap())
        };
        let mut tls = layer.connect(raw).await.unwrap();
        let mut request = vec![0x00];
        request.extend_from_slice(&uuid);
        request.extend_from_slice(&[18, 0x0a, 0x10]);
        request.extend_from_slice(b"xtls-rprx-vision");
        request.push(0x03);
        tls.write_all(&request).await.unwrap();
        tls.flush().await.unwrap();
        Self {
            stream: tls,
            uuid,
            first_sent: false,
            deframer: VisionDeframer::new(),
            decoder: XudpDecoder::new(),
        }
    }

    /// Send one batch of XUDP bytes as a single CONTINUE vision frame
    /// (zero padding — legal on the wire and simplest for the harness).
    async fn send(&mut self, xudp_bytes: &[u8]) {
        let mut frame = Vec::new();
        if !self.first_sent {
            frame.extend_from_slice(&self.uuid);
            self.first_sent = true;
        }
        frame.push(0x00);
        frame.extend_from_slice(&(xudp_bytes.len() as u16).to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(xudp_bytes);
        self.stream.write_all(&frame).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    async fn recv_frame(&mut self) -> Option<XudpFrame> {
        loop {
            if let Some(f) = self.decoder.next_frame() {
                return Some(f);
            }
            let mut buf = [0u8; 8192];
            let n = self.stream.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            let mut content = Vec::new();
            self.deframer.feed(&buf[..n], &mut content);
            if !content.is_empty() {
                self.decoder.feed(&content).ok()?;
            }
        }
    }

    async fn recv_frame_timed(&mut self) -> XudpFrame {
        timeout(T, self.recv_frame())
            .await
            .expect("reply frame timeout")
            .expect("connection closed while awaiting a reply frame")
    }

    /// Read raw bytes until EOF/error or `within` elapses; returns true
    /// when the connection closed, false on timeout (still open).
    async fn closed_within(&mut self, within: Duration) -> bool {
        let mut buf = [0u8; 512];
        matches!(
            timeout(within, self.stream.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }
}

/// Assert a reply frame is a Keep+Data with exact payload, returning the
/// wire source target it carries.
fn assert_keep_data(
    frame: &XudpFrame,
    sid: u16,
    payload: &[u8],
) -> meow_proxy::mux::xudp::XudpTarget {
    let XudpFrame::Keep {
        session_id,
        target,
        payload: got,
    } = frame
    else {
        panic!("expected Keep+Data, got {frame:?}");
    };
    assert_eq!(*session_id, sid, "reply session id");
    assert_eq!(got.as_deref(), Some(payload), "reply payload byte-exact");
    target
        .clone()
        .expect("server replies always carry the real source")
}

fn assert_ipv4_source(target: &meow_proxy::mux::xudp::XudpTarget, ip: [u8; 4], port: u16) {
    use meow_proxy::mux::xudp::XudpAddr;
    assert_eq!(
        target.addr,
        XudpAddr::Ipv4(std::net::Ipv4Addr::from(ip)),
        "reply source address"
    );
    assert_eq!(target.port, port, "reply source port");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_echo_end_to_end_meow_client() {
    let echo = start_udp_echo("127.0.0.1:0").await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-echo",
    )
    .await;

    let adapter = vision_tls_adapter(port, ALICE);
    let meta = Metadata {
        network: Network::Udp,
        dst_ip: Some(echo.ip()),
        dst_port: echo.port(),
        ..Default::default()
    };
    let conn = timeout(T, adapter.dial_udp(&meta))
        .await
        .expect("udp dial timeout")
        .expect("udp dial");
    for payload in [b"xudp-one".as_slice(), &[0xabu8; 1200][..]] {
        timeout(T, conn.write_packet(payload, &echo))
            .await
            .expect("write timeout")
            .expect("write");
        let mut buf = vec![0u8; 2048];
        let (n, src) = timeout(T, conn.read_packet(&mut buf))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(&buf[..n], payload, "echoed payload byte-exact");
        assert_eq!(src.port(), echo.port(), "reply source is the echo server");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_multi_session_isolation_and_interleave() {
    let e1 = start_udp_echo("127.0.0.1:0").await;
    let e2 = start_udp_echo("127.0.0.1:0").await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-multi",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    // Two sessions in one batch, traffic interleaved across both.
    let mut batch = Vec::new();
    batch.extend_from_slice(&new_data(
        3,
        &v4_target([127, 0, 0, 1], e1.port()),
        b"a-one",
    ));
    batch.extend_from_slice(&new_data(
        5,
        &v4_target([127, 0, 0, 1], e2.port()),
        b"b-one",
    ));
    batch.extend_from_slice(&keep_data(3, None, b"a-two"));
    batch.extend_from_slice(&keep_data(5, None, b"b-two"));
    client.send(&batch).await;

    let mut seen = std::collections::HashMap::new();
    for _ in 0..4 {
        let frame = client.recv_frame_timed().await;
        let XudpFrame::Keep {
            session_id,
            target,
            payload,
        } = frame
        else {
            panic!("expected Keep+Data, got {frame:?}");
        };
        seen.entry(session_id).or_insert_with(Vec::new).push((
            target.expect("reply source"),
            payload.expect("payload").to_vec(),
        ));
    }
    let s3 = seen.remove(&3).expect("session 3 replies");
    let s5 = seen.remove(&5).expect("session 5 replies");
    assert_eq!(s3.len(), 2);
    assert_eq!(s5.len(), 2);
    // Session isolation: each session's replies come only from its own
    // target, in send order.
    assert_eq!(s3[0].1, b"a-one");
    assert_eq!(s3[1].1, b"a-two");
    assert_eq!(s5[0].1, b"b-one");
    assert_eq!(s5[1].1, b"b-two");
    for (src, _) in &s3 {
        assert_ipv4_source(src, [127, 0, 0, 1], e1.port());
    }
    for (src, _) in &s5 {
        assert_ipv4_source(src, [127, 0, 0, 1], e2.port());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_per_packet_target_change_and_default() {
    let e1 = start_udp_echo("127.0.0.1:0").await;
    let e2 = start_udp_echo("127.0.0.1:0").await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-targets",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    // New to e1, then a per-packet override to e2, then a bare Keep that
    // must fall back to the session default (e1).
    client
        .send(&new_data(
            7,
            &v4_target([127, 0, 0, 1], e1.port()),
            b"to-e1",
        ))
        .await;
    client
        .send(&keep_data(
            7,
            Some(&v4_target([127, 0, 0, 1], e2.port())),
            b"to-e2",
        ))
        .await;
    client.send(&keep_data(7, None, b"back-to-e1")).await;

    // Replies from different targets ride independent flows: ordering is
    // only guaranteed per flow, so match the three distinct payloads
    // rather than their arrival order.
    let mut matched = std::collections::HashMap::new();
    for _ in 0..3 {
        let frame = client.recv_frame_timed().await;
        let XudpFrame::Keep {
            session_id,
            target,
            payload,
        } = frame
        else {
            panic!("expected Keep+Data, got {frame:?}");
        };
        assert_eq!(session_id, 7);
        matched.insert(
            payload.expect("payload").to_vec(),
            target.expect("reply source"),
        );
    }
    assert_ipv4_source(
        matched.get(b"to-e1".as_slice()).expect("e1 reply"),
        [127, 0, 0, 1],
        e1.port(),
    );
    assert_ipv4_source(
        matched.get(b"to-e2".as_slice()).expect("e2 reply"),
        [127, 0, 0, 1],
        e2.port(),
    );
    assert_ipv4_source(
        matched
            .get(b"back-to-e1".as_slice())
            .expect("default-target reply"),
        [127, 0, 0, 1],
        e1.port(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_domain_target_reply_rewrites_to_domain() {
    use meow_proxy::mux::xudp::XudpAddr;
    let echo = start_udp_echo("127.0.0.1:0").await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_hosts(&[], &[("echo.test", "127.0.0.1".parse().unwrap())]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-domain",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    client
        .send(&new_data(
            9,
            &domain_target("echo.test", echo.port()),
            b"domain-probe",
        ))
        .await;
    let frame = client.recv_frame_timed().await;
    let src = assert_keep_data(&frame, 9, b"domain-probe");
    // xray freedom semantics: the reply came from the IP the domain
    // resolved to, so the wire source is rewritten to the original domain.
    assert_eq!(
        src.addr,
        XudpAddr::Domain("echo.test".into()),
        "domain target's reply source must be rewritten to the domain"
    );
    assert_eq!(src.port, echo.port());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_ipv6_target() {
    use meow_proxy::mux::xudp::XudpAddr;
    let echo = start_udp_echo("[::1]:0").await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-v6",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    client
        .send(&new_data(
            11,
            &v6_target(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                echo.port(),
            ),
            b"v6-probe",
        ))
        .await;
    let frame = client.recv_frame_timed().await;
    let src = assert_keep_data(&frame, 11, b"v6-probe");
    assert_eq!(src.addr, XudpAddr::Ipv6(std::net::Ipv6Addr::LOCALHOST));
    assert_eq!(src.port, echo.port());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_datagram_boundaries_preserved() {
    let echo = start_udp_echo("127.0.0.1:0").await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-bounds",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    let target = v4_target([127, 0, 0, 1], echo.port());
    let p1 = vec![0x01u8; 1];
    let p2 = vec![0x02u8; 100];
    let p3 = vec![0x03u8; 1400];
    // One batch: New carrying the first datagram plus two more datagrams —
    // the replies must arrive as three separate frames, neither merged
    // nor split.
    let mut batch = new_data(13, &target, &p1);
    batch.extend_from_slice(&keep_data(13, None, &p2));
    batch.extend_from_slice(&keep_data(13, None, &p3));
    client.send(&batch).await;

    let f1 = client.recv_frame_timed().await;
    assert_keep_data(&f1, 13, &p1);
    let f2 = client.recv_frame_timed().await;
    assert_keep_data(&f2, 13, &p2);
    let f3 = client.recv_frame_timed().await;
    assert_keep_data(&f3, 13, &p3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_upstream_reply_cap_boundary_and_oversize_drop() {
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);

    // 8192 exactly is the inclusive wire cap: the complete datagram must
    // survive byte-for-byte through the bounded upstream read buffer.
    let exact_reply = start_udp_fixed_reply("127.0.0.1:0", 8192).await;
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel.clone(),
        "vless-xudp-cap8192",
    )
    .await;
    let mut client = RawXudpClient::connect(port, ALICE).await;
    let target = v4_target([127, 0, 0, 1], exact_reply.port());
    client.send(&new_data(21, &target, b"trigger")).await;
    let frame = client.recv_frame_timed().await;
    assert_keep_data(&frame, 21, &vec![0x5au8; 8192]);
    drop(client);

    // One byte beyond the cap is dropped whole. The following marker on
    // the same session proves no truncated 8192-byte frame was forwarded.
    let oversize_reply = start_udp_oversize_then_echo("127.0.0.1:0", 8193).await;
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-cap8193",
    )
    .await;
    let mut client = RawXudpClient::connect(port, ALICE).await;
    let target = v4_target([127, 0, 0, 1], oversize_reply.port());
    let mut batch = new_data(22, &target, b"trigger");
    batch.extend_from_slice(&keep_data(22, None, b"marker"));
    client.send(&batch).await;
    let frame = client.recv_frame_timed().await;
    assert_keep_data(&frame, 22, b"marker");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_fatal_teardown_is_bounded_when_writer_is_blocked() {
    let reply_source = start_udp_fixed_reply("127.0.0.1:0", 8192).await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let listener = Arc::new(
        VlessListener::new(
            tunnel,
            "vless-xudp-blocked-teardown".into(),
            tls_spec(&cert, &key, vec![("alice", ALICE)]),
        )
        .unwrap()
        .with_max_connections(1),
    );
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    listener.note_bound_endpoint(socket.local_addr().unwrap());
    let task_listener = Arc::clone(&listener);
    let _task = tokio::spawn(async move {
        let _ = task_listener.run_on(socket).await;
    });

    // A tiny client receive buffer plus 128 cap-sized replies leaves the
    // server writer parked in TCP backpressure. The client deliberately
    // does not read while queueing that work.
    let mut client = RawXudpClient::connect_with_recv_buffer(port, ALICE, Some(4096)).await;
    let target = v4_target([127, 0, 0, 1], reply_source.port());
    let mut batch = Vec::new();
    for sid in 1..=128u16 {
        batch.extend_from_slice(&new_data(sid, &target, b"trigger"));
    }
    client.send(&batch).await;
    sleep(Duration::from_millis(300)).await;

    // Fatal ingress while the writer is blocked: teardown must bound the
    // writer join and close the physical connection instead of waiting
    // for the peer to drain a megabyte it is refusing to read.
    let mut fatal = new_data(129, &target, b"");
    fatal.truncate(fatal.len() - 2);
    fatal.extend_from_slice(&8193u16.to_be_bytes());
    fatal.extend_from_slice(&[0u8; 64]);
    client.send(&fatal).await;

    // The listener cap is one connection. Once teardown's bounded writer
    // join fires, the first handler releases that slot and a second XUDP
    // association works even though the first client still refuses to read.
    sleep(Duration::from_millis(700)).await;
    let echo = start_udp_echo("127.0.0.1:0").await;
    let mut second = RawXudpClient::connect(port, ALICE).await;
    second
        .send(&new_data(
            1,
            &v4_target([127, 0, 0, 1], echo.port()),
            b"slot-free",
        ))
        .await;
    let frame = second.recv_frame_timed().await;
    assert_keep_data(&frame, 1, b"slot-free");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_tcp_new_kills_connection() {
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-tcpnew",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    // network byte 0x01 (TCP) on a UDP-only vision mux: connection-fatal.
    let tcp_meta = udp_target_meta(0x01, 443, 0x01, &[127, 0, 0, 1]);
    client.send(&new_data(1, &tcp_meta, b"tcp-in-xudp")).await;
    assert!(
        client.closed_within(Duration::from_secs(3)).await,
        "a TCP New must kill the whole connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_udp_false_refuses_mux_at_vless_layer() {
    let echo = start_udp_echo("127.0.0.1:0").await;
    let _ = echo;
    let (cert, key) = tls_cert();
    let mut spec = tls_spec(&cert, &key, vec![("alice", ALICE)]);
    spec.udp = false;
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(spec, tunnel, "vless-xudp-udpfalse").await;

    // The VLESS Mux request itself is refused before any XUDP byte: the
    // connection closes without a response header.
    let mut client = RawXudpClient::connect(port, ALICE).await;
    client
        .send(&new_data(1, &v4_target([127, 0, 0, 1], echo.port()), b"x"))
        .await;
    assert!(
        client.closed_within(Duration::from_secs(3)).await,
        "udp:false must refuse the Mux command at the VLESS layer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_oversized_meta_and_payload_kill_connection() {
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-oversize",
    )
    .await;

    // meta_len 513 exceeds the 512 cap — fatal before any allocation.
    let mut client = RawXudpClient::connect(port, ALICE).await;
    let mut evil = Vec::new();
    evil.extend_from_slice(&513u16.to_be_bytes());
    evil.extend_from_slice(&[0u8; 40]);
    client.send(&evil).await;
    assert!(
        client.closed_within(Duration::from_secs(3)).await,
        "meta_len over the 512 cap must kill the connection"
    );

    // payload_len 8193 exceeds the 8192 cap — fatal at the length field.
    let mut client = RawXudpClient::connect(port, ALICE).await;
    let mut evil = new_data(1, &v4_target([127, 0, 0, 1], 53), b"");
    // Rebuild manually: valid meta but payload_len field overstated.
    evil.truncate(evil.len() - 2); // drop the zero payload_len for clarity
    evil.extend_from_slice(&8193u16.to_be_bytes());
    evil.extend_from_slice(&[0u8; 64]);
    client.send(&evil).await;
    assert!(
        client.closed_within(Duration::from_secs(3)).await,
        "payload_len over the 8192 cap must kill the connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_unknown_sid_data_answers_end_and_connection_survives() {
    let echo = start_udp_echo("127.0.0.1:0").await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-unknownsid",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    // Data on a session the server never opened: xray answers an End
    // frame and drops the datagram — not connection-fatal.
    client.send(&keep_data(42, None, b"orphan")).await;
    let frame = client.recv_frame_timed().await;
    let XudpFrame::End { session_id, error } = frame else {
        panic!("expected End for the unknown session, got {frame:?}");
    };
    assert_eq!(session_id, 42);
    assert!(!error);

    // The connection is alive: a valid session right after still echoes.
    client
        .send(&new_data(
            1,
            &v4_target([127, 0, 0, 1], echo.port()),
            b"alive",
        ))
        .await;
    let frame = client.recv_frame_timed().await;
    assert_keep_data(&frame, 1, b"alive");
}

// --- teardown accounting: probe outbound counting dials and closes ----------

struct ProbeConn {
    probe: Arc<ProbeState>,
    parked: AtomicBool,
}

struct ProbeState {
    dials: AtomicUsize,
    closes: AtomicUsize,
    writes: AtomicUsize,
}

#[async_trait::async_trait]
impl ProxyPacketConn for ProbeConn {
    async fn read_packet(&self, _buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
        // No replies ever arrive; close() unblocks nothing here, the task
        // simply dies with its abort — exactly the shape teardown must
        // handle through the conn guard.
        std::future::pending().await
    }
    async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> meow_common::Result<usize> {
        self.probe.writes.fetch_add(1, Ordering::Relaxed);
        let _ = &self.parked;
        Ok(buf.len())
    }
    fn local_addr(&self) -> meow_common::Result<SocketAddr> {
        Ok("127.0.0.1:0".parse().unwrap())
    }
    fn close(&self) -> meow_common::Result<()> {
        self.probe.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct ProbeUdpProxy {
    probe: Arc<ProbeState>,
    health: meow_common::ProxyHealth,
}

#[async_trait::async_trait]
impl meow_common::ProxyAdapter for ProbeUdpProxy {
    fn name(&self) -> &str {
        "probe-udp"
    }
    fn adapter_type(&self) -> meow_common::AdapterType {
        meow_common::AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        true
    }
    async fn dial_tcp(
        &self,
        _metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
        Err(meow_common::MeowError::NotSupported("no tcp".into()))
    }
    async fn dial_udp(
        &self,
        _metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
        self.probe.dials.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(ProbeConn {
            probe: Arc::clone(&self.probe),
            parked: AtomicBool::new(false),
        }))
    }
    fn health(&self) -> &meow_common::ProxyHealth {
        &self.health
    }
}

impl meow_common::Proxy for ProbeUdpProxy {
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
    fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
        Vec::new()
    }
}

fn probe_tunnel(probe: &Arc<ProbeState>) -> (Tunnel, Arc<ProbeUdpProxy>) {
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
    let proxy = Arc::new(ProbeUdpProxy {
        probe: Arc::clone(probe),
        health: meow_common::ProxyHealth::new(),
    });
    let mut proxies = res.proxies;
    proxies.insert(
        "probe-udp".into(),
        Arc::clone(&proxy) as Arc<dyn meow_common::Proxy>,
    );
    tunnel.update_proxies(proxies, res.dialer_registry);
    tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
        "probe-udp",
    ))]);
    (tunnel, proxy)
}

async fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
    for _ in 0..150 {
        if cond() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_teardown_cancels_accepted_connections() {
    let echo = start_tcp_echo().await;
    let (cert, key) = tls_cert();
    let tunnel = tunnel_with_rules(&[]);
    let (port, _listener, accept_task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-accept-teardown",
    )
    .await;

    let adapter = vision_tls_adapter(port, ALICE);
    let mut conn = timeout(T, adapter.dial_tcp(&metadata(echo)))
        .await
        .expect("dial timeout")
        .expect("dial");
    echo_roundtrip(&mut *conn, b"before-teardown")
        .await
        .expect("connection works before accept-loop teardown");

    accept_task.abort();
    let _ = accept_task.await;

    // Cancelling the accept loop must cancel the supervised connection too,
    // not leave an established relay detached behind the closed socket.
    let mut closed = false;
    for _ in 0..40 {
        if echo_roundtrip(&mut *conn, b"after-teardown").await.is_err() {
            closed = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        closed,
        "established connection survived accept-loop cancellation as a detached task"
    );
}

/// Read the fixed VLESS request header for a plain (non-Vision) UDP-over-TCP
/// client. The mock only needs to consume it; every fixture target is valid.
async fn consume_plain_vless_udp_request(stream: &mut TcpStream) {
    let mut fixed = [0u8; 1 + 16 + 1 + 1 + 2 + 1];
    stream.read_exact(&mut fixed).await.unwrap();
    assert_eq!(fixed[0], 0, "VLESS version");
    let addon_len = fixed[17] as usize;
    if addon_len > 0 {
        let mut addon = vec![0u8; addon_len];
        stream.read_exact(&mut addon).await.unwrap();
    }
    assert_eq!(fixed[18], 0x02, "mock expects the UDP command");
    let port = u16::from_be_bytes([fixed[19], fixed[20]]);
    assert_ne!(port, 0);
    match fixed[21] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await.unwrap();
        }
        0x02 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            let mut addr = vec![0u8; len[0] as usize];
            stream.read_exact(&mut addr).await.unwrap();
        }
        0x03 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await.unwrap();
        }
        other => panic!("unexpected VLESS address type {other}"),
    }
}

/// A one-connection plain VLESS UDP server. Its first reply is deliberately
/// larger than the flow's raw-encapsulation read buffer; the client-side
/// VLESS packet conn drains that whole framed datagram and reports a
/// recoverable buffer error. The next reply is normal and must still be
/// deliverable.
async fn start_plain_vless_oversize_then_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        consume_plain_vless_udp_request(&mut stream).await;
        let mut first = true;
        let mut wrote_response_header = false;
        loop {
            let mut len = [0u8; 2];
            if stream.read_exact(&mut len).await.is_err() {
                return;
            }
            let len = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0u8; len];
            if stream.read_exact(&mut payload).await.is_err() {
                return;
            }
            let reply = if first {
                first = false;
                vec![0x5au8; 16 * 1024]
            } else {
                payload
            };
            let mut out = Vec::new();
            if !wrote_response_header {
                wrote_response_header = true;
                out.extend_from_slice(&[0, 0]);
            }
            out.extend_from_slice(&(reply.len() as u16).to_be_bytes());
            out.extend_from_slice(&reply);
            if stream.write_all(&out).await.is_err() {
                return;
            }
            if stream.flush().await.is_err() {
                return;
            }
        }
    });
    addr
}

fn tunnel_with_named_proxy(name: &str, proxy: Arc<dyn meow_common::Proxy>) -> Tunnel {
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
    let mut proxies = res.proxies;
    proxies.insert(name.into(), proxy);
    tunnel.update_proxies(proxies, res.dialer_registry);
    tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(name))]);
    tunnel
}

/// Acceptance test for the F11 cross-crate fix: passes only once
/// meow-common carries a matchable "packet consumed but oversized" error
/// (e.g. `MeowError::UdpPacketTooLarge`), meow-proxy's framed UDP readers
/// emit it after fully draining the datagram, and the XUDP flow replies
/// loop treats it as drop-this-packet rather than flow-fatal. Until then
/// the flow dies and the marker never arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the F11 cross-crate error type in meow-common/meow-proxy; see vless_xudp module docs"]
async fn xudp_plain_vless_oversize_reply_drops_packet_not_flow() {
    let server = start_plain_vless_oversize_then_echo().await;
    let outbound: Arc<dyn meow_common::Proxy> = Arc::new(
        meow_config::proxy_parser::WrappedProxy::new(Box::new(VlessAdapter::new(
            "plain-vless",
            "127.0.0.1",
            server.port(),
            [0x44; 16],
            None,
            true,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        ))),
    );
    let tunnel = tunnel_with_named_proxy("plain-vless", outbound);
    let (cert, key) = tls_cert();
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-plain-oversize",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    let target = v4_target([127, 0, 0, 1], 15353);
    let mut batch = new_data(31, &target, b"trigger");
    batch.extend_from_slice(&keep_data(31, None, b"marker"));
    client.send(&batch).await;

    // The 8193-byte reply is consumed upstream and dropped whole. The flow
    // must stay alive to deliver this later normal reply on the same sid.
    let frame = timeout(Duration::from_secs(3), client.recv_frame())
        .await
        .expect("normal reply after a consumed oversize reply")
        .expect("connection closed after a consumed oversize reply");
    assert_keep_data(&frame, 31, b"marker");
}

struct GatedDialState {
    started: AtomicUsize,
    completed: AtomicUsize,
    open: tokio::sync::Notify,
}

struct GatedDialConn;

#[async_trait::async_trait]
impl ProxyPacketConn for GatedDialConn {
    async fn read_packet(&self, _buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
    async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> meow_common::Result<usize> {
        Ok(buf.len())
    }
    fn local_addr(&self) -> meow_common::Result<SocketAddr> {
        Ok("127.0.0.1:0".parse().unwrap())
    }
    fn close(&self) -> meow_common::Result<()> {
        Ok(())
    }
}

struct GatedDialProxy {
    state: Arc<GatedDialState>,
    health: meow_common::ProxyHealth,
}

#[async_trait::async_trait]
impl meow_common::ProxyAdapter for GatedDialProxy {
    fn name(&self) -> &str {
        "gated-udp"
    }
    fn adapter_type(&self) -> meow_common::AdapterType {
        meow_common::AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        true
    }
    async fn dial_tcp(
        &self,
        _metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
        Err(meow_common::MeowError::NotSupported("no tcp".into()))
    }
    async fn dial_udp(
        &self,
        _metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
        self.state.started.fetch_add(1, Ordering::Relaxed);
        self.state.open.notified().await;
        self.state.completed.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(GatedDialConn))
    }
    fn health(&self) -> &meow_common::ProxyHealth {
        &self.health
    }
}

impl meow_common::Proxy for GatedDialProxy {
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
    fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
        Vec::new()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_flush_races_flow_establishment_and_cancels_the_dial() {
    let state = Arc::new(GatedDialState {
        started: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        open: tokio::sync::Notify::new(),
    });
    let proxy = Arc::new(GatedDialProxy {
        state: Arc::clone(&state),
        health: meow_common::ProxyHealth::new(),
    });
    let tunnel = tunnel_with_named_proxy("gated-udp", proxy);
    let (cert, key) = tls_cert();
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel.clone(),
        "vless-xudp-flush-establish",
    )
    .await;

    let mut client = RawXudpClient::connect(port, ALICE).await;
    client
        .send(&new_data(
            41,
            &v4_target([127, 0, 0, 1], 15353),
            b"flush-me",
        ))
        .await;
    wait_until(
        || state.started.load(Ordering::Relaxed) == 1,
        "the flow dial to start",
    )
    .await;

    assert_eq!(
        tunnel.close_all_udp_sessions(),
        1,
        "the establishing flow's flush watch is live"
    );
    state.open.notify_one();
    sleep(Duration::from_millis(150)).await;
    assert_eq!(
        state.completed.load(Ordering::Relaxed),
        0,
        "a flow flushed while establishing must cancel rather than complete its dial"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_teardown_reaps_every_flow_socket() {
    let (cert, key) = tls_cert();
    let probe = Arc::new(ProbeState {
        dials: AtomicUsize::new(0),
        closes: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    });
    let (tunnel, _proxy) = probe_tunnel(&probe);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-teardown",
    )
    .await;

    let target = v4_target([127, 0, 0, 1], 15353);
    {
        let mut client = RawXudpClient::connect(port, ALICE).await;
        let mut batch = new_data(1, &target, b"one");
        batch.extend_from_slice(&new_data(2, &target, b"two"));
        client.send(&batch).await;
        wait_until(
            || probe.dials.load(Ordering::Relaxed) == 2,
            "two flow dials",
        )
        .await;
        // Abrupt client death: no End frames, just a dropped connection.
        drop(client);
    }
    wait_until(
        || probe.closes.load(Ordering::Relaxed) == 2,
        "both flow sockets closed at connection teardown",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xudp_end_frame_tears_down_only_its_session() {
    let (cert, key) = tls_cert();
    let probe = Arc::new(ProbeState {
        dials: AtomicUsize::new(0),
        closes: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    });
    let (tunnel, _proxy) = probe_tunnel(&probe);
    let (port, _listener, _task) = start_listener(
        tls_spec(&cert, &key, vec![("alice", ALICE)]),
        tunnel,
        "vless-xudp-endframe",
    )
    .await;

    let target = v4_target([127, 0, 0, 1], 15353);
    let mut client = RawXudpClient::connect(port, ALICE).await;
    let mut batch = new_data(1, &target, b"one");
    batch.extend_from_slice(&new_data(2, &target, b"two"));
    client.send(&batch).await;
    wait_until(
        || probe.dials.load(Ordering::Relaxed) == 2,
        "two flow dials",
    )
    .await;

    // End session 1: exactly one upstream conn dies, session 2 keeps
    // delivering. Fresh data on the ended sid answers an End frame.
    client.send(&end_frame(1)).await;
    wait_until(
        || probe.closes.load(Ordering::Relaxed) == 1,
        "session 1's flow closed by the End frame",
    )
    .await;
    let writes_before = probe.writes.load(Ordering::Relaxed);
    let mut batch = keep_data(2, None, b"still-alive");
    batch.extend_from_slice(&keep_data(1, None, b"corpse"));
    client.send(&batch).await;
    let frame = client.recv_frame_timed().await;
    assert!(
        matches!(frame, XudpFrame::End { session_id: 1, .. }),
        "data on the ended session answers End, got {frame:?}"
    );
    wait_until(
        || probe.writes.load(Ordering::Relaxed) > writes_before,
        "session 2 still delivering upstream",
    )
    .await;
    assert_eq!(
        probe.closes.load(Ordering::Relaxed),
        1,
        "no extra flow died"
    );
}
