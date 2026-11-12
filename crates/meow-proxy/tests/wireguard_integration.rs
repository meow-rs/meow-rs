#![cfg(feature = "wireguard")]
//! WireGuard adapter integration (issue #899 Phase-1, spec §7.3).
//!
//! Two layers are exercised here over **real loopback UDP** — no external
//! binaries, no TUN device:
//!
//! - `adapter_handshake_and_udp_datagram_decapsulates_at_peer`: a real
//!   `WireGuardAdapter` → pump actor → endpoint UDP socket ↔ a responder
//!   `meow_wireguard::Tunn` playing the WG peer. The test performs a real
//!   Noise handshake, sends one UDP flow datagram through
//!   `dial_udp`/`write_packet`, and asserts the decapsulated inner packet
//!   is the expected IPv4+UDP datagram byte-for-byte (tunnel source
//!   address, destination, payload). This is the honest MVP gate: the
//!   adapter → smoltcp → boringtun → wire → peer path is proven end to
//!   end in-process. (The pure `Tunn`↔`Tunn` crypto/transport roundtrip
//!   without the adapter lives in `meow-wireguard/tests/wg_vectors.rs`.)
//!
//! - `reserved_bytes_mutate_outbound_wire_datagrams`: the same real wire,
//!   asserting the post-encapsulation `reserved` mutation (bytes 1–4 of
//!   the WG header) leaves the pump — the Cloudflare WARP client
//!   identifier. A standard peer treats non-zero reserved bytes as an
//!   invalid packet (boringtun reads the first 4 bytes as one LE type
//!   word), so the assertion happens on the *raw datagram* at the socket,
//!   and the test only proves mutation on the wire, not interop with a
//!   WARP-unaware responder.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use meow_common::{AdapterType, MeowError, Metadata, Network, ProxyAdapter};
use meow_proxy::{WireGuardAdapter, WireGuardConfig};
use meow_wireguard::x25519::{PublicKey, StaticSecret};
use meow_wireguard::{Tunn, TunnResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The initiator's fixed secret (any 32 bytes are a valid unclamped
/// secret); the responder peer is [0x22; 32].
const INITIATOR_PRIVATE: [u8; 32] = [0x11u8; 32];
const RESPONDER_PRIVATE: [u8; 32] = [0x22u8; 32];

fn wg_config(endpoint: SocketAddr, reserved: Option<[u8; 3]>) -> WireGuardConfig {
    let responder_public = PublicKey::from(&StaticSecret::from(RESPONDER_PRIVATE));
    WireGuardConfig {
        name: "wg-test".into(),
        server: endpoint.ip().to_string(),
        port: endpoint.port(),
        private_key: INITIATOR_PRIVATE,
        public_key: *responder_public.as_bytes(),
        pre_shared_key: None,
        ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ipv6: None,
        // Empty → the adapter applies the catch-all 0.0.0.0/0 + ::/0.
        allowed_ips: vec![],
        reserved,
        mtu: 1420,
        udp: true,
        remote_dns_resolve: true,
        persistent_keepalive: 0,
        dns: vec![],
    }
}

#[test]
fn adapter_surface_reports_type_addr_and_udp_support() {
    let adapter = WireGuardAdapter::new(wg_config("127.0.0.1:51820".parse().unwrap(), None))
        .expect("valid config constructs");
    assert_eq!(adapter.name(), "wg-test");
    assert_eq!(adapter.adapter_type(), AdapterType::WireGuard);
    // IPv4-literal endpoints normalize to host:port display form.
    assert_eq!(adapter.addr(), "127.0.0.1:51820");
    assert!(adapter.support_udp());

    let no_udp = WireGuardAdapter::new(WireGuardConfig {
        udp: false,
        ..wg_config("127.0.0.1:51820".parse().unwrap(), None)
    })
    .unwrap();
    assert!(!no_udp.support_udp());
}

#[test]
fn adapter_new_rejects_bad_material() {
    let mut cfg = wg_config("127.0.0.1:51820".parse().unwrap(), None);
    cfg.private_key = [0u8; 32];
    assert!(WireGuardAdapter::new(cfg).is_err(), "all-zero private key");

    let mut cfg = wg_config("127.0.0.1:51820".parse().unwrap(), None);
    cfg.server.clear();
    assert!(WireGuardAdapter::new(cfg).is_err(), "empty server");

    let mut cfg = wg_config("127.0.0.1:51820".parse().unwrap(), None);
    cfg.port = 0;
    assert!(WireGuardAdapter::new(cfg).is_err(), "zero port");

    // inner_mtu = 600 - 64 = 536 < 576 → the adapter's own floor.
    let mut cfg = wg_config("127.0.0.1:51820".parse().unwrap(), None);
    cfg.mtu = 600;
    assert!(WireGuardAdapter::new(cfg).is_err(), "mtu too small");
}

/// IPv4+UDP datagram assertion: `pkt` is a raw inner tunnel packet —
/// version 4, protocol 17, `src` → `dst`, destination port and payload.
fn assert_ipv4_udp(pkt: &[u8], src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, payload: &[u8]) {
    assert!(pkt.len() >= 28, "IPv4+UDP packet is at least 28B: {pkt:?}");
    assert_eq!(pkt[0] >> 4, 4, "IPv4 version nibble: {pkt:?}");
    assert_eq!(pkt[9], 17, "IPv4 protocol must be UDP (17): {pkt:?}");
    assert_eq!(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]), src);
    assert_eq!(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]), dst);
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let udp = &pkt[ihl..];
    assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), dst_port);
    assert_eq!(
        &udp[8..8 + payload.len()],
        payload,
        "UDP payload must survive the tunnel byte-for-byte"
    );
}

/// One UDP flow end to end: adapter → smoltcp → Noise session → real UDP
/// → responder `Tunn` → decapsulated inner packet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_handshake_and_udp_datagram_decapsulates_at_peer() {
    // ── Responder side: a real UDP socket driven by a responder Tunn ──
    let responder_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind responder");
    let endpoint = responder_sock.local_addr().unwrap();
    let initiator_public = PublicKey::from(&StaticSecret::from(INITIATOR_PRIVATE));
    let mut responder_tunn = Tunn::new(
        StaticSecret::from(RESPONDER_PRIVATE),
        initiator_public,
        None,
        None,
        7,
        None,
    );
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let responder_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut dst = vec![0u8; 2048];
        loop {
            let (n, peer) = responder_sock.recv_from(&mut buf).await.expect("recv_from");
            let mut datagram: &[u8] = &buf[..n];
            // boringtun contract: a `WriteToNetwork` result means "call
            // again with an empty datagram" until it stops producing
            // output — that is how packets queued behind the handshake
            // flush onto the wire.
            loop {
                match responder_tunn.decapsulate(None, datagram, &mut dst) {
                    TunnResult::WriteToNetwork(pkt) => {
                        let out = pkt.to_vec();
                        responder_sock.send_to(&out, peer).await.expect("send_to");
                        datagram = &[];
                    }
                    TunnResult::WriteToTunnelV4(plain, _) => {
                        let _ = seen_tx.send(plain.to_vec()).await;
                        break;
                    }
                    TunnResult::WriteToTunnelV6(..) | TunnResult::Done | TunnResult::Err(_) => {
                        break
                    }
                }
            }
        }
    });

    // ── Initiator side: the real adapter + pump ───────────────────────
    let adapter = WireGuardAdapter::new(wg_config(endpoint, None)).expect("construct adapter");
    let dst_addr: SocketAddr = "10.9.9.9:53".parse().unwrap();
    let meta = Metadata {
        network: Network::Udp,
        dst_ip: Some(dst_addr.ip()),
        dst_port: dst_addr.port(),
        ..Metadata::default()
    };
    let conn = adapter.dial_udp(&meta).await.expect("udp bind");
    conn.write_packet(b"meow-ping", &dst_addr)
        .await
        .expect("write_packet");

    // ── The peer must see the decapsulated datagram ───────────────────
    let inner = tokio::time::timeout(Duration::from_secs(15), seen_rx.recv())
        .await
        .expect("handshake + datagram must decapsulate within 15s")
        .expect("responder stays up");
    assert_ipv4_udp(
        &inner,
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 9, 9, 9),
        53,
        b"meow-ping",
    );

    adapter.reset_sessions();
    responder_task.abort();
}

/// `remote-dns-resolve: false` must refuse a domain dial at resolve time —
/// before any pump work happens (spec §4.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_dns_resolve_false_rejects_domain_dial() {
    let adapter = WireGuardAdapter::new(WireGuardConfig {
        remote_dns_resolve: false,
        ..wg_config("127.0.0.1:51820".parse().unwrap(), None)
    })
    .expect("construct adapter");
    // `localhost` is deliberately resolvable: an `example.invalid` dial
    // would fail in DNS anyway, so the assertion could not tell the flag
    // check from a lookup failure. `remote-dns-resolve: false` must fire
    // *before* resolution — the message names the flag.
    let meta = Metadata {
        network: Network::Tcp,
        host: "localhost".into(),
        dst_port: 443,
        ..Metadata::default()
    };
    match adapter.dial_tcp(&meta).await {
        Err(MeowError::Dns(e)) => {
            assert!(
                e.contains("remote-dns-resolve"),
                "flag error must name remote-dns-resolve, got: {e}"
            );
        }
        Err(e) => panic!("expected Dns error for a domain dial, got {e:?}"),
        Ok(_) => panic!("expected Dns error for a domain dial, got a live conn"),
    }
}

/// The `reserved` WARP identifier is a post-encapsulation mutation of
/// bytes 1–4 of every outbound WG datagram (boringtun has no reserved-byte
/// API). Asserted on the raw wire datagram — a standard responder rejects
/// mutated packets, so this leg only watches the wire for a few sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_bytes_mutate_outbound_wire_datagrams() {
    const RESERVED: [u8; 3] = [13, 53, 133];

    let responder_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind responder");
    let endpoint = responder_sock.local_addr().unwrap();
    let adapter =
        WireGuardAdapter::new(wg_config(endpoint, Some(RESERVED))).expect("construct adapter");

    // Any dial spawns the pump, which kicks the WG handshake immediately.
    let meta = Metadata {
        network: Network::Udp,
        dst_ip: Some(Ipv4Addr::new(10, 9, 9, 9).into()),
        dst_port: 53,
        ..Metadata::default()
    };
    let _conn = adapter.dial_udp(&meta).await.expect("udp bind");

    // Watch the raw wire: every datagram the pump emits (handshake
    // initiation and its retransmissions) must carry the reserved bytes —
    // byte 0 is the message type, bytes 1..4 are the field WARP reads.
    let mut checked = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 2048];
    while checked < 2 {
        let (n, _peer) = tokio::time::timeout_at(deadline, responder_sock.recv_from(&mut buf))
            .await
            .expect("the pump must emit WG datagrams")
            .expect("recv_from");
        assert!(n >= 4, "WG datagram has a 4-byte type+reserved word");
        assert_eq!(&buf[1..4], &RESERVED, "reserved bytes must be written");
        checked += 1;
    }

    adapter.reset_sessions();
}

// ── raw inner-packet crafting ───────────────────────────────────────────

/// RFC 1071 one's-complement checksum.
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, rem) = data.as_chunks::<2>();
    for &w in chunks {
        sum += u32::from(u16::from_be_bytes(w));
    }
    if let Some(&b) = rem.first() {
        sum += u32::from(b) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

/// A decapsulated inner IPv4+TCP segment, fields the responder needs.
struct TcpSeg<'a> {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
    payload: &'a [u8],
}

fn parse_ipv4_tcp(pkt: &[u8]) -> Option<TcpSeg<'_>> {
    if pkt.len() < 40 || pkt[0] >> 4 != 4 || pkt[9] != 6 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if pkt.len() < ihl + 20 {
        return None;
    }
    let t = &pkt[ihl..];
    let off = usize::from(t[12] >> 4) * 4;
    if t.len() < off {
        return None;
    }
    Some(TcpSeg {
        src_ip: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        dst_ip: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
        sport: u16::from_be_bytes([t[0], t[1]]),
        dport: u16::from_be_bytes([t[2], t[3]]),
        seq: u32::from_be_bytes(t[4..8].try_into().ok()?),
        flags: t[13],
        payload: &t[off..],
    })
}

/// Both halves of a TCP 4-tuple for packet crafting.
struct TcpEnds {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
}

/// A checksummed IPv4+TCP segment — smoltcp drops checksum failures
/// silently, so the pseudo-header checksum must be real.
fn build_ipv4_tcp(ends: &TcpEnds, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&ends.src.octets());
    pkt[16..20].copy_from_slice(&ends.dst.octets());
    let ip_sum = inet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    {
        let t = &mut pkt[20..];
        t[0..2].copy_from_slice(&ends.sport.to_be_bytes());
        t[2..4].copy_from_slice(&ends.dport.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&64240u16.to_be_bytes());
        t[20..].copy_from_slice(payload);
    }
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&ends.src.octets());
    pseudo.extend_from_slice(&ends.dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&pkt[20..]);
    let c = inet_checksum(&pseudo);
    pkt[36..38].copy_from_slice(&c.to_be_bytes());
    pkt
}

/// IPv4+UDP datagram with checksum 0 (legal for IPv4 per RFC 768).
fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_sum = inet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let u = &mut pkt[20..];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // u[6..8] checksum stays 0.
    u[8..].copy_from_slice(payload);
    pkt
}

/// The responder side of every real-wire test: a UDP socket + a responder
/// `Tunn`. `on_inner` is called with each decapsulated inner packet and
/// may return an inner packet to encapsulate back to the initiator.
async fn spawn_responder<F>(
    mut on_inner: F,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
)
where
    F: FnMut(&[u8]) -> Option<Vec<u8>> + Send + 'static,
{
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind responder");
    let endpoint = sock.local_addr().unwrap();
    let initiator_public = PublicKey::from(&StaticSecret::from(INITIATOR_PRIVATE));
    let mut tunn = Tunn::new(
        StaticSecret::from(RESPONDER_PRIVATE),
        initiator_public,
        None,
        None,
        7,
        None,
    );
    let initiations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let inits = std::sync::Arc::clone(&initiations);
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut dst = vec![0u8; 2048];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await.expect("recv_from");
            if n >= 4 && buf[0] == 1 {
                inits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            let mut datagram: &[u8] = &buf[..n];
            loop {
                match tunn.decapsulate(None, datagram, &mut dst) {
                    TunnResult::WriteToNetwork(pkt) => {
                        let out = pkt.to_vec();
                        sock.send_to(&out, peer).await.expect("send_to");
                        datagram = &[];
                    }
                    TunnResult::WriteToTunnelV4(plain, _)
                    | TunnResult::WriteToTunnelV6(plain, _) => {
                        if let Some(inner) = on_inner(plain) {
                            let mut out = vec![0u8; 2048];
                            match tunn.encapsulate(&inner, &mut out) {
                                TunnResult::WriteToNetwork(w) => {
                                    let w = w.to_vec();
                                    sock.send_to(&w, peer).await.expect("reply");
                                }
                                other => panic!("encapsulate: {other:?}"),
                            }
                        }
                        break;
                    }
                    TunnResult::Done | TunnResult::Err(_) => break,
                }
            }
        }
    });
    (endpoint, task, initiations)
}

/// TCP through the whole path end to end: smoltcp SYN → responder's
/// crafted SYN-ACK → Established → payload echoed back byte-for-byte.
/// This is the test that pins the pre-Established EOF race: a `Closed`
/// event queued while the socket sat in SynSent would make the very first
/// `poll_read` on the delivered stream return EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_stream_echoes_through_full_tunnel() {
    // The responder speaks just enough TCP to be an echo server: server
    // sequence space starts at 5000 and advances per byte (SYN/FIN count
    // as one).
    let mut srv_next = 5001u32;
    let (endpoint, responder_task, _inits) = spawn_responder(move |pkt| {
        let seg = parse_ipv4_tcp(pkt)?;
        let (seq, ack, flags, payload): (u32, u32, u8, Vec<u8>) =
            if seg.flags & TCP_SYN != 0 && seg.flags & TCP_ACK == 0 {
                (5000, seg.seq.wrapping_add(1), TCP_SYN | TCP_ACK, Vec::new())
            } else if seg.flags & TCP_FIN != 0 {
                let reply = (
                    srv_next,
                    seg.seq
                        .wrapping_add(u32::try_from(seg.payload.len()).unwrap())
                        .wrapping_add(1),
                    TCP_FIN | TCP_ACK,
                    Vec::new(),
                );
                srv_next = srv_next.wrapping_add(1);
                reply
            } else if !seg.payload.is_empty() {
                let len = u32::try_from(seg.payload.len()).unwrap();
                let reply = (
                    srv_next,
                    seg.seq.wrapping_add(len),
                    TCP_PSH | TCP_ACK,
                    seg.payload.to_vec(),
                );
                srv_next = srv_next.wrapping_add(len);
                reply
            } else {
                return None; // pure ACK / keepalive — nothing to answer
            };
        Some(build_ipv4_tcp(
            &TcpEnds {
                src: seg.dst_ip,
                dst: seg.src_ip,
                sport: seg.dport,
                dport: seg.sport,
            },
            seq,
            ack,
            flags,
            &payload,
        ))
    })
    .await;
    let adapter = WireGuardAdapter::new(wg_config(endpoint, None)).expect("construct adapter");
    let meta = Metadata {
        network: Network::Tcp,
        dst_ip: Some(Ipv4Addr::new(10, 9, 9, 9).into()),
        dst_port: 443,
        host: "10.9.9.9".into(),
        ..Metadata::default()
    };
    let mut conn = tokio::time::timeout(Duration::from_secs(15), adapter.dial_tcp(&meta))
        .await
        .expect("dial must finish within the WG handshake window")
        .expect("dial_tcp");
    conn.write_all(b"meow-tcp-echo")
        .await
        .expect("stream write");
    let mut buf = vec![0u8; b"meow-tcp-echo".len()];
    tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut buf))
        .await
        .expect("echo must return within 10s")
        .expect("stream read");
    assert_eq!(&buf, b"meow-tcp-echo", "echo must round-trip byte-for-byte");

    adapter.reset_sessions();
    responder_task.abort();
}

/// UDP ingress: the responder encapsulates an inner IPv4+UDP reply back
/// to the flow's socket — proves `decapsulate` → device rx → smoltcp →
/// `read_packet` delivery, not just egress.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_ingress_reaches_read_packet() {
    let (endpoint, responder_task, _inits) = spawn_responder(|pkt| {
        if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
            return None;
        }
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        let u = &pkt[ihl..];
        let sport = u16::from_be_bytes([u[0], u[1]]);
        let dport = u16::from_be_bytes([u[2], u[3]]);
        let payload = &u[8..];
        if payload != b"meow-ping" {
            return None;
        }
        Some(build_ipv4_udp(
            Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
            Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
            dport,
            sport,
            b"meow-pong",
        ))
    })
    .await;
    let adapter = WireGuardAdapter::new(wg_config(endpoint, None)).expect("construct adapter");
    let dst_addr: SocketAddr = "10.9.9.9:53".parse().unwrap();
    let meta = Metadata {
        network: Network::Udp,
        dst_ip: Some(dst_addr.ip()),
        dst_port: dst_addr.port(),
        ..Metadata::default()
    };
    let conn = adapter.dial_udp(&meta).await.expect("udp bind");
    conn.write_packet(b"meow-ping", &dst_addr)
        .await
        .expect("write_packet");

    let mut buf = [0u8; 512];
    let (n, src) = tokio::time::timeout(Duration::from_secs(15), conn.read_packet(&mut buf))
        .await
        .expect("reply must arrive within 15s")
        .expect("read_packet");
    assert_eq!(&buf[..n], b"meow-pong", "ingress payload byte-for-byte");
    assert_eq!(src, dst_addr, "reply source is the inner destination");

    adapter.reset_sessions();
    responder_task.abort();
}

/// `allowed-ips` and tunnel-family policy reject at the adapter — before
/// any handshake work — at both dial_tcp and dial_udp (spec §3.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_rejects_outside_allowed_ips_and_family() {
    let adapter = WireGuardAdapter::new(WireGuardConfig {
        // v4 target inside the declared range; v6 covered by ::/0 so the
        // family check (not the allowed-ips check) is what fires for v6.
        allowed_ips: vec!["10.0.0.0/8".parse().unwrap(), "::/0".parse().unwrap()],
        ..wg_config("127.0.0.1:51820".parse().unwrap(), None)
    })
    .expect("construct adapter");

    let meta = Metadata {
        network: Network::Udp,
        dst_ip: Some(Ipv4Addr::new(8, 8, 8, 8).into()),
        dst_port: 53,
        ..Metadata::default()
    };
    let err = adapter
        .dial_udp(&meta)
        .await
        .err()
        .expect("udp dial outside allowed-ips must fail");
    assert!(
        err.to_string().contains("outside allowed-ips"),
        "udp dial outside allowed-ips must name the policy: {err}"
    );

    let meta = Metadata {
        network: Network::Tcp,
        dst_ip: Some("fd00::1".parse().unwrap()),
        dst_port: 443,
        ..Metadata::default()
    };
    let err = adapter
        .dial_tcp(&meta)
        .await
        .err()
        .expect("v6 dial without a v6 tunnel address must fail");
    assert!(
        matches!(err, MeowError::NotSupported(_)),
        "v6 dial without a v6 tunnel address must be NotSupported: {err:?}"
    );
}

/// A burst of concurrent first dials must open exactly one pump and emit
/// exactly one WG handshake initiation — `spawn_lock` exists because a
/// duplicate initiation both wastes an endpoint socket and trips peer
/// rate limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_dials_share_one_handshake() {
    let (endpoint, responder_task, initiations) = spawn_responder(|_| None).await;
    let adapter = std::sync::Arc::new(WireGuardAdapter::new(wg_config(endpoint, None)).unwrap());
    let dst_addr: SocketAddr = "10.9.9.9:53".parse().unwrap();
    let meta = Metadata {
        network: Network::Udp,
        dst_ip: Some(dst_addr.ip()),
        dst_port: dst_addr.port(),
        ..Metadata::default()
    };

    let mut joins = Vec::new();
    for _ in 0..4 {
        let a = std::sync::Arc::clone(&adapter);
        let m = meta.clone();
        joins.push(tokio::spawn(async move { a.dial_udp(&m).await }));
    }
    for j in joins {
        j.await
            .expect("dial task")
            .expect("each concurrent dial_udp must succeed");
    }
    // Let the handshake finish, then look at the wire: exactly one
    // initiation (type byte 1) — a second pump would have sent its own.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        initiations.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "concurrent first dials must share one handshake"
    );

    adapter.reset_sessions();
    responder_task.abort();
}
