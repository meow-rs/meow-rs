//! WireGuard inbound integration tests (`tests/wireguard_listener.rs`).
//!
//! Two in-process clients drive the listener over loopback UDP:
//!
//! - `meow_proxy::WireGuardAdapter` — the real userspace WG outbound —
//!   for the end-to-end TCP/UDP legs (spec §11.2's first rows);
//! - a raw `meow_wireguard::Tunn` + UDP socket for the legs the adapter
//!   cannot reach from its bound endpoint: endpoint roaming, unknown-
//!   peer silence, and forged inner sources for the ACL leg.
//!
//! The upstream side is always a loopback echo server behind a DIRECT
//! tunnel — no real network, no external binary.

#![cfg(feature = "listener-wireguard")]

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::{direct_tunnel, spawn_echo_server};
use meow_common::{ConnType, Metadata, Network, ProxyAdapter, ProxyPacketConn};
use meow_listener::{
    SnifferRuntime, WgListenerSpec, WgPeerSpec, WireGuardListener, WireGuardListenerGuard,
};
use meow_proxy::{WireGuardAdapter, WireGuardConfig};
use meow_wireguard::{x25519, Tunn, TunnResult};
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{timeout, timeout_at};

const LISTENER_MTU: u16 = 1420;

/// One-shot tracing init so `cargo test -- --nocapture` shows the
/// actor's debug!/trace! lines on demand.
fn init_logs() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();
}

const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
/// Any wait that is not the actual assertion — generous so a loaded CI
/// box never decides a leg.
const OP_TIMEOUT: Duration = Duration::from_secs(10);
/// Negative-assertion window: long enough that a reply that *would*
/// come arrives in unit-test-scale time, short enough to keep the
/// suite fast. Roaming replies traverse a real flow task + echo RTT,
/// so they are well under a second.
const SILENT_WINDOW: Duration = Duration::from_millis(800);

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = x25519::StaticSecret::from([seed; 32]);
    let public = x25519::PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// The server's static pair is fixed per test via seeds; helpers take
/// the material rather than reaching for globals.
fn server_keypair() -> ([u8; 32], [u8; 32]) {
    keypair(0x5E)
}

fn peer_spec(public: [u8; 32], allowed: &[&str]) -> WgPeerSpec {
    WgPeerSpec {
        public_key: public,
        preshared_key: None,
        allowed_ips: allowed.iter().map(|s| s.parse().unwrap()).collect(),
        name: SmolStr::new(""),
        reserved: None,
    }
}

/// Spawn a listener bound on an ephemeral loopback port; returns the
/// guard and the bound port (mirrors the app's bind-before-spawn).
fn spawn_listener(
    tunnel: meow_tunnel::Tunnel,
    private_key: [u8; 32],
    peers: Vec<WgPeerSpec>,
    max_connections: usize,
    sniffer: Option<Arc<SnifferRuntime>>,
) -> (WireGuardListenerGuard, SocketAddr) {
    let sock = WireGuardListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = sock.local_addr().unwrap();
    let spec = WgListenerSpec {
        private_key,
        peers,
        mtu: LISTENER_MTU,
        udp: true,
        udp_timeout: Duration::from_secs(30),
    };
    let mut listener = WireGuardListener::new(tunnel, spec, "wg-itest".into())
        .with_max_connections(max_connections);
    if let Some(rt) = sniffer {
        listener = listener.with_sniffer(rt);
    }
    let guard = listener.spawn(sock).expect("actor spawns");
    (guard, bound)
}

/// A `WireGuardAdapter` pointed at the test listener — the in-process
/// client the spec's §11.3 calls for.
fn client_adapter(
    name: &str,
    private_key: [u8; 32],
    server_public: [u8; 32],
    listen: SocketAddr,
    ip: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> WireGuardAdapter {
    WireGuardAdapter::new(WireGuardConfig {
        name: name.into(),
        server: listen.ip().to_string(),
        port: listen.port(),
        private_key,
        public_key: server_public,
        pre_shared_key: None,
        ip,
        ipv6,
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
        reserved: None,
        mtu: LISTENER_MTU,
        udp: true,
        remote_dns_resolve: false,
        persistent_keepalive: 0,
        dns: vec![],
    })
    .expect("adapter config valid")
}

fn tcp_meta(dst: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        host: dst.ip().to_string().into(),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        ..Default::default()
    }
}

fn udp_meta(dst: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Udp,
        conn_type: ConnType::Inner,
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        ..Default::default()
    }
}

/// Loopback UDP echo: replies every datagram byte-for-byte.
async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if sock.send_to(&buf[..n], from).await.is_err() {
                break;
            }
        }
    });
    addr
}

// ── raw-Tunn client ─────────────────────────────────────────────────

/// Minimal IPv4 packet `src`→`dst` carrying `l4` — the listener's inner
/// parser needs version/IHL/no-fragment/proto only (the UDP checksum is
/// zero: legal on v4, and the inner UDP path does not verify it).
fn inner_udp_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    // checksum stays 0 (v4 "no checksum")
    p[28..].copy_from_slice(payload);
    p
}

/// A bare client `Tunn` — the hand-driven leg for roaming/forged-source
/// tests the boxed adapter cannot express.
struct RawClient {
    tunn: Tunn,
    work: Vec<u8>,
}

impl RawClient {
    fn new(private_key: [u8; 32], server_public: [u8; 32], slot: usize) -> Self {
        Self {
            tunn: Tunn::new(
                x25519::StaticSecret::from(private_key),
                x25519::PublicKey::from(server_public),
                None,
                None,
                slot as u32,
                None,
            ),
            work: vec![0u8; 4096],
        }
    }

    /// One full handshake over `sock`: init → response → keepalive.
    /// Panics on any silence (the negative tests use [`Self::send_init`]
    /// directly instead).
    async fn handshake(&mut self, sock: &UdpSocket, listen: SocketAddr) {
        let init = self.init_datagram();
        sock.send_to(&init, listen).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = timeout(OP_TIMEOUT, async {
            sock.recv_from(&mut buf).await.unwrap().0
        })
        .await
        .expect("handshake response within timeout");
        let keepalive = {
            let TunnResult::WriteToNetwork(b) =
                self.tunn
                    .decapsulate(Some(listen.ip()), &buf[..n], &mut self.work)
            else {
                panic!("response decapsulates to keepalive")
            };
            b.to_vec()
        };
        sock.send_to(&keepalive, listen).await.unwrap();
    }

    fn init_datagram(&mut self) -> Vec<u8> {
        let TunnResult::WriteToNetwork(b) =
            self.tunn.format_handshake_initiation(&mut self.work, false)
        else {
            panic!("initiation formats")
        };
        b.to_vec()
    }

    /// Encapsulate an inner IP packet and send it from `sock`.
    async fn send_inner(&mut self, sock: &UdpSocket, listen: SocketAddr, inner: &[u8]) {
        let datagram = {
            let TunnResult::WriteToNetwork(b) = self.tunn.encapsulate(inner, &mut self.work) else {
                panic!("encapsulate yields wire data")
            };
            b.to_vec()
        };
        sock.send_to(&datagram, listen).await.unwrap();
    }

    /// Receive one datagram on `sock` and decapsulate it; returns the
    /// recovered inner packet. Any `WriteToNetwork` result (e.g. a
    /// keepalive reply) is answered and the loop retries.
    async fn recv_inner(
        &mut self,
        sock: &UdpSocket,
        listen: SocketAddr,
        within: Duration,
    ) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let Ok(n) = timeout_at(deadline, async {
                sock.recv_from(&mut buf).await.unwrap().0
            })
            .await
            else {
                return None;
            };
            match self.tunn.decapsulate(None, &buf[..n], &mut self.work) {
                TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                    return Some(pkt.to_vec());
                }
                TunnResult::WriteToNetwork(b) => {
                    let reply = b.to_vec();
                    let _ = sock.send_to(&reply, listen).await;
                }
                _ => {}
            }
        }
    }
}

/// Read `pkt`'s UDP payload (v4, no options).
fn udp_payload_v4(pkt: &[u8]) -> &[u8] {
    assert_eq!(pkt[0] >> 4, 4, "inner reply is IPv4");
    &pkt[28..]
}

// ── §11.2 legs ──────────────────────────────────────────────────────

/// `listener_tcp_echo_end_to_end`: adapter `dial_tcp` to an arbitrary
/// inner dst → listener smoltcp accept → `route_inbound_tcp` → DIRECT
/// to the loopback echo — byte-exact both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_tcp_echo_end_to_end() {
    init_logs();
    let (srv_priv, srv_pub) = server_keypair();
    let (client_priv, client_pub) = keypair(0xA0);
    let echo = spawn_echo_server().await;
    let tunnel = direct_tunnel();
    let (_guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![peer_spec(client_pub, &["10.0.0.0/8"])],
        0,
        None,
    );
    let client = client_adapter("wg-a", client_priv, srv_pub, listen, Some(CLIENT_V4), None);

    let mut conn = timeout(OP_TIMEOUT, client.dial_tcp(&tcp_meta(echo)))
        .await
        .expect("dial resolves")
        .expect("dial_tcp through listener");
    let payload = b"wg-inbound echo across the tunnel";
    conn.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    timeout(OP_TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("echo within timeout")
        .unwrap();
    assert_eq!(&buf, payload);
}

/// `listener_udp_echo_end_to_end`: `dial_udp` → listener flow table →
/// DIRECT `dial_udp` → loopback echo → reply packet byte-exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_udp_echo_end_to_end() {
    init_logs();
    let (srv_priv, srv_pub) = server_keypair();
    let (client_priv, client_pub) = keypair(0xA0);
    let echo = spawn_udp_echo().await;
    let tunnel = direct_tunnel();
    let (_guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![peer_spec(client_pub, &["10.0.0.0/8"])],
        0,
        None,
    );
    let client = client_adapter("wg-a", client_priv, srv_pub, listen, Some(CLIENT_V4), None);

    let conn: Box<dyn ProxyPacketConn> = timeout(OP_TIMEOUT, client.dial_udp(&udp_meta(echo)))
        .await
        .expect("bind resolves")
        .expect("dial_udp through listener");
    let payload = b"wg-udp-inner";
    let mut buf = vec![0u8; 256];
    // First datagram may race the flow's upstream dial — retry like a
    // real UDP client (mirrors the SS listener tests' retransmit note).
    let deadline = tokio::time::Instant::now() + OP_TIMEOUT;
    let n = loop {
        conn.write_packet(payload, &echo).await.unwrap();
        match timeout(Duration::from_millis(500), conn.read_packet(&mut buf)).await {
            Ok(Ok((n, from))) => {
                assert_eq!(from, echo);
                break n;
            }
            Ok(Err(e)) => panic!("udp read: {e}"),
            Err(_) if tokio::time::Instant::now() < deadline => continue,
            Err(_) => panic!("udp echo did not arrive within {OP_TIMEOUT:?}"),
        }
    };
    assert_eq!(&buf[..n], payload);
}

/// `listener_tcp_echo_v6` (§13.7's v4/v6 split): a `fd00::` client dials
/// `[::1]` — the v6 AnyIP listener path mirrors v4's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_tcp_echo_v6() {
    // Skip on v6-less hosts rather than fail — CI has ::1 everywhere.
    let Ok(v6_probe) = tokio::net::TcpListener::bind("[::1]:0").await else {
        return;
    };
    drop(v6_probe);

    let (srv_priv, srv_pub) = server_keypair();
    let (client_priv, client_pub) = keypair(0xA0);
    // Bind the echo on ::1 — the client's inner dst is the real address.
    let echo_listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let echo = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let tunnel = direct_tunnel();
    // The inner source for a ::1 dial is ::1 itself (the client's stack
    // picks the destination-affine address), so the peer ACL must admit
    // it alongside the client's own tunnel address.
    let (_guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![peer_spec(client_pub, &["fd00::/8", "::1/128"])],
        0,
        None,
    );
    let client = client_adapter("wg-v6", client_priv, srv_pub, listen, None, Some(CLIENT_V6));

    let mut conn = timeout(OP_TIMEOUT, client.dial_tcp(&tcp_meta(echo)))
        .await
        .expect("dial resolves")
        .expect("v6 dial_tcp through listener");
    let payload = b"wg-inbound v6 echo";
    conn.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    timeout(OP_TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("echo within timeout")
        .unwrap();
    assert_eq!(&buf, payload);
}

/// `listener_multi_peer_isolation`: two registered peers hold
/// independent sessions and flow tables; a forged inner source (peer
/// B's `allowed_ips` is a single /32 — the crafted packet claims a
/// different one) is silently dropped while peer A's flows stay up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_multi_peer_isolation() {
    let (srv_priv, srv_pub) = server_keypair();
    let (priv_a, pub_a) = keypair(0xA0);
    let (priv_b, pub_b) = keypair(0xB0);
    let echo = spawn_echo_server().await;
    let udp_echo = spawn_udp_echo().await;
    let tunnel = direct_tunnel();
    let (_guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![
            // Peer B's ACL admits exactly one inner source; the forged
            // packet below claims another and must drop.
            peer_spec(pub_a, &["10.0.0.0/8"]),
            peer_spec(pub_b, &["10.0.0.2/32"]),
        ],
        0,
        None,
    );

    // Peer A: adapter TCP echo.
    let client_a = client_adapter("wg-a", priv_a, srv_pub, listen, Some(CLIENT_V4), None);
    let mut conn_a = timeout(OP_TIMEOUT, client_a.dial_tcp(&tcp_meta(echo)))
        .await
        .expect("dial resolves")
        .expect("peer A dial_tcp");
    conn_a.write_all(b"peer-a").await.unwrap();
    let mut buf = vec![0u8; 6];
    timeout(OP_TIMEOUT, conn_a.read_exact(&mut buf))
        .await
        .expect("peer A echo")
        .unwrap();
    assert_eq!(&buf, b"peer-a");

    // Peer B: raw client — first a legit inner source (10.0.0.2 ∈
    // 10.0.0.2/32) gets a reply, then the same session sending from a
    // forged source (10.0.0.9 ∉ ACL) gets silence.
    let mut raw_b = RawClient::new(priv_b, srv_pub, 1);
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    raw_b.handshake(&sock_b, listen).await;

    let legit = inner_udp_v4(
        CLIENT_V4,
        Ipv4Addr::LOCALHOST,
        5555,
        udp_echo.port(),
        b"b-legit",
    );
    raw_b.send_inner(&sock_b, listen, &legit).await;
    let reply = raw_b
        .recv_inner(&sock_b, listen, OP_TIMEOUT)
        .await
        .expect("legit source gets a UDP reply");
    assert_eq!(udp_payload_v4(&reply), b"b-legit");

    let forged = inner_udp_v4(
        "10.0.0.9".parse().unwrap(),
        Ipv4Addr::LOCALHOST,
        5556,
        udp_echo.port(),
        b"b-forged",
    );
    raw_b.send_inner(&sock_b, listen, &forged).await;
    assert!(
        raw_b
            .recv_inner(&sock_b, listen, SILENT_WINDOW)
            .await
            .is_none(),
        "forged inner source outside allowed_ips must be silently dropped"
    );

    // Peer A's established flow is unaffected by B's noise.
    conn_a.write_all(b"still-a").await.unwrap();
    let mut buf2 = vec![0u8; 7];
    timeout(OP_TIMEOUT, conn_a.read_exact(&mut buf2))
        .await
        .expect("peer A still echoes")
        .unwrap();
    assert_eq!(&buf2, b"still-a");
}

/// `listener_roaming_relearns_endpoint`: an authenticated datagram from
/// a *new* UDP source port moves the peer's endpoint — the next reply
/// lands on the new socket and the old one stays silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_roaming_relearns_endpoint() {
    let (srv_priv, srv_pub) = server_keypair();
    let (client_priv, client_pub) = keypair(0xA0);
    let udp_echo = spawn_udp_echo().await;
    let tunnel = direct_tunnel();
    let (_guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![peer_spec(client_pub, &["10.0.0.0/8"])],
        0,
        None,
    );

    let mut raw = RawClient::new(client_priv, srv_pub, 0);
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    raw.handshake(&sock_a, listen).await;

    // Session lives on endpoint A; an authenticated datagram from B
    // re-learns the endpoint (WG roaming semantics).
    let pkt = inner_udp_v4(
        CLIENT_V4,
        "127.0.0.1".parse().unwrap(),
        7777,
        udp_echo.port(),
        b"roam",
    );
    raw.send_inner(&sock_b, listen, &pkt).await;

    let reply = raw
        .recv_inner(&sock_b, listen, OP_TIMEOUT)
        .await
        .expect("reply follows the roamed endpoint to socket B");
    assert_eq!(udp_payload_v4(&reply), b"roam");

    // The stale endpoint gets nothing more.
    assert!(
        raw.recv_inner(&sock_a, listen, SILENT_WINDOW)
            .await
            .is_none(),
        "roamed-away endpoint must not receive the reply"
    );
}

/// `listener_unknown_peer_quiet`: a handshake initiation from an
/// unregistered static key gets no response and creates no session —
/// verified by socket-level silence (the demux already pins the table
/// side).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_unknown_peer_quiet() {
    let (srv_priv, srv_pub) = server_keypair();
    let (_known_priv, known_pub) = keypair(0xA0);
    let (rogue_priv, _rogue_pub) = keypair(0x77);
    let tunnel = direct_tunnel();
    let (_guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![peer_spec(known_pub, &["10.0.0.0/8"])],
        0,
        None,
    );

    let mut rogue = RawClient::new(rogue_priv, srv_pub, 0);
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let init = rogue.init_datagram();
    sock.send_to(&init, listen).await.unwrap();
    let mut buf = vec![0u8; 2048];
    assert!(
        timeout(SILENT_WINDOW, sock.recv_from(&mut buf))
            .await
            .is_err(),
        "unregistered peer initiation must be silently dropped"
    );
}

/// `listener_tcp_backpressure`: `max_connections = 1` — conn #2 to the
/// same inner port is refused (RST from the aborted accept) while the
/// established conn keeps flowing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_tcp_backpressure() {
    let (srv_priv, srv_pub) = server_keypair();
    let (client_priv, client_pub) = keypair(0xA0);
    let echo = spawn_echo_server().await;
    let tunnel = direct_tunnel();
    let (_guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![peer_spec(client_pub, &["10.0.0.0/8"])],
        1, // one inner flow, TCP+UDP combined
        None,
    );
    let client = client_adapter("wg-a", client_priv, srv_pub, listen, Some(CLIENT_V4), None);

    let mut first = timeout(OP_TIMEOUT, client.dial_tcp(&tcp_meta(echo)))
        .await
        .expect("dial resolves")
        .expect("first conn");
    first.write_all(b"cap-1").await.unwrap();
    let mut buf = vec![0u8; 5];
    timeout(OP_TIMEOUT, first.read_exact(&mut buf))
        .await
        .expect("first echo")
        .unwrap();

    // The second conn to the *same* port hits the already-registered
    // listener — smoltcp accepts, the post-poll cap gate aborts → RST.
    let refused = timeout(OP_TIMEOUT, client.dial_tcp(&tcp_meta(echo)))
        .await
        .expect("dial resolves");
    assert!(refused.is_err(), "second conn must be refused at cap");

    // The survivor is untouched.
    first.write_all(b"cap-ok").await.unwrap();
    let mut buf = vec![0u8; 6];
    timeout(OP_TIMEOUT, first.read_exact(&mut buf))
        .await
        .expect("first conn still echoes")
        .unwrap();
    assert_eq!(&buf, b"cap-ok");
}

/// `listener_tcp_sniff_host`: an inner ClientHello's SNI lands in
/// `metadata.sniff_host` → the DOMAIN rule sees it — `blocked.example`
/// is REJECTed while another SNI reaches DIRECT's echo.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_tcp_sniff_host() {
    let (srv_priv, srv_pub) = server_keypair();
    let (client_priv, client_pub) = keypair(0xA0);
    let echo = spawn_echo_server().await;

    // DOMAIN rule on the sniffed name → REJECT; MATCH → DIRECT.
    let yaml = "rules:\n  - DOMAIN,blocked.example,REJECT\n  - MATCH,DIRECT\n";
    let raw = meow_config::parse_raw_yaml(yaml).unwrap();
    let res = meow_config::rebuild_from_raw(&raw).unwrap();
    let tunnel = direct_tunnel();
    tunnel.set_mode(meow_common::TunnelMode::Rule);
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.update_rules(res.rules);

    let sniffer = Arc::new(SnifferRuntime::new(meow_common::SnifferConfig {
        enable: true,
        tls_ports: vec![echo.port()],
        timeout: Duration::from_secs(2),
        ..Default::default()
    }));
    let (_guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![peer_spec(client_pub, &["10.0.0.0/8"])],
        0,
        Some(sniffer),
    );
    let client = client_adapter("wg-a", client_priv, srv_pub, listen, Some(CLIENT_V4), None);

    // Blocked SNI → REJECTed flow (the conn closes; read sees EOF).
    let mut blocked = timeout(OP_TIMEOUT, client.dial_tcp(&tcp_meta(echo)))
        .await
        .expect("dial resolves")
        .expect("blocked-SNI conn establishes at WG level");
    blocked
        .write_all(&build_client_hello("blocked.example"))
        .await
        .unwrap();
    let mut byte = [0u8; 1];
    let seen = timeout(OP_TIMEOUT, blocked.read(&mut byte))
        .await
        .expect("read resolves");
    match seen {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("rejected flow must not relay {n} bytes"),
    }

    // Any other SNI → MATCH,DIRECT → the hello bytes echo back (the
    // sniff prefix is replayed upstream, not consumed).
    let mut open = timeout(OP_TIMEOUT, client.dial_tcp(&tcp_meta(echo)))
        .await
        .expect("dial resolves")
        .expect("open-SNI conn");
    let hello = build_client_hello("allowed.example");
    open.write_all(&hello).await.unwrap();
    let mut buf = vec![0u8; hello.len()];
    timeout(OP_TIMEOUT, open.read_exact(&mut buf))
        .await
        .expect("echo within timeout")
        .unwrap();
    assert_eq!(buf, hello, "sniff prefix must reach the upstream");
}

/// `listener_shutdown_drain`: `shutdown()` stops the actor, `wait`
/// reaps the thread, and the endpoint socket is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_shutdown_drain() {
    let (srv_priv, srv_pub) = server_keypair();
    let (client_priv, client_pub) = keypair(0xA0);
    let tunnel = direct_tunnel();
    let (guard, listen) = spawn_listener(
        tunnel,
        srv_priv,
        vec![peer_spec(client_pub, &["10.0.0.0/8"])],
        0,
        None,
    );
    // Prove the actor was actually up before asking it to stop.
    let client = client_adapter("wg-a", client_priv, srv_pub, listen, Some(CLIENT_V4), None);
    let _echo = spawn_echo_server().await;
    let conn = timeout(OP_TIMEOUT, client.dial_tcp(&tcp_meta(_echo)))
        .await
        .expect("dial resolves")
        .expect("pre-shutdown conn");
    drop(conn);
    drop(client);

    guard.shutdown();
    timeout(OP_TIMEOUT, guard.wait())
        .await
        .expect("actor joins within timeout")
        .expect("clean shutdown");

    // The endpoint socket went with the actor — the port is free.
    UdpSocket::bind(listen)
        .await
        .expect("listener port released after shutdown");
}

/// Minimal TLS ClientHello carrying `hostname` in the SNI extension —
/// the sniffer.rs unit-test fixture, duplicated here because the test
/// needs the bytes on the *client* side.
fn build_client_hello(hostname: &str) -> Vec<u8> {
    let name_bytes = hostname.as_bytes();
    let sni_entry_len = 3 + name_bytes.len();
    let sni_list_len = sni_entry_len;
    let sni_ext_data_len = 2 + sni_list_len;

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name_bytes);

    let extensions_len = sni_ext.len();
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0u8; 32]);
    hello.push(0x00);
    hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    hello.extend_from_slice(&sni_ext);

    let handshake_len = hello.len();
    let mut handshake = vec![
        0x01,
        ((handshake_len >> 16) & 0xff) as u8,
        ((handshake_len >> 8) & 0xff) as u8,
        (handshake_len & 0xff) as u8,
    ];
    handshake.extend_from_slice(&hello);

    let record_len = handshake.len();
    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(record_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Keep `IpAddr`/`TunnResult` referenced on rust-analyzer-only paths —
/// the types above use them through the fully qualified form already.
#[allow(dead_code)]
const _: () = {
    fn _refs(_: IpAddr, _: TunnResult<'static>) {}
};
