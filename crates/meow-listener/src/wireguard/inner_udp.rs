//! Inner-UDP termination for the WireGuard inbound.
//!
//! Unlike TCP there is no smoltcp socket: a decrypted UDP datagram is
//! self-contained, so the actor keys a flow table on
//! `(peer_slot, inner_src, inner_dst)` and hands the payload to a
//! per-flow task that dials through the normal tunnel
//! (`TunnelInner::dial_udp`, the SOCKS5-UDP/TProxy routing path).
//! Replies come back through the flow's `read_packet`, get wrapped in a
//! hand-built inner IP+UDP reply ([`build_reply`]) on the flow task —
//! off the actor — and are injected into the actor's encrypt queue
//! keyed by peer slot so the reply takes the *originating* peer's
//! session and endpoint (spec §5: replies route by source peer).
//!
//! Resource bounds mirror the TProxy UDP path: a bounded payload queue
//! per flow ([`UDP_FLOW_QUEUE`]), drop-on-full semantics, an
//! idle-timeout eviction the task enforces itself (reset on each
//! successful write *and* each relayed reply), and the actor's
//! `max_connections` cap counting UDP flows together with TCP
//! connections.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use meow_common::{ConnType, Metadata, Network};
use meow_tunnel::TunnelInner;
use meow_tunnel::{MatchedRule, UsingProxy};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant as TokioInstant};
use tracing::{debug, info};

/// Per-flow payload queue bound (client→remote direction). A full
/// queue drops the datagram — UDP drop semantics, same as TProxy's
/// `FLOW_QUEUE`.
pub(super) const UDP_FLOW_QUEUE: usize = 64;

/// Largest buffer the flow's reply reader keeps — any IP datagram the
/// outbound returns. Replies that exceed the inner MTU after header
/// wrapping are dropped at [`build_reply`], never fragmented and never
/// answered with ICMP fragmentation-needed (spec §6).
const DATAGRAM_BUF: usize = 64 * 1024;

/// One inner-UDP flow as the actor sees it — just the send half of the
/// payload queue. Idle timing lives entirely in the flow task (its
/// timer resets on *both* directions), so the actor's only sweep
/// signal is `tx.is_closed()`: a dead task drops `rx` and the send
/// half reports closed.
pub(super) struct UdpFlow {
    pub tx: mpsc::Sender<Bytes>,
}

/// Flow-table key: the peer namespace is part of the key, so two peers
/// may share an inner `(src→dst)` tuple without colliding — replies
/// still reach the right session.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(super) struct UdpFlowKey {
    pub slot: usize,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// What the actor hands to [`spawn_flow`]: everything the task needs
/// without borrowing the actor.
pub(super) struct FlowArgs {
    pub inner: Arc<TunnelInner>,
    pub in_name: Arc<str>,
    pub in_port: u16,
    pub slot: usize,
    /// Inner source of the datagrams — the peer's claimed client
    /// address; replies are built *to* this.
    pub client: SocketAddr,
    /// Inner destination the peer dialed; replies are built *from*
    /// this (the flow answers as the destination the client wrote to).
    pub orig_dst: SocketAddr,
    pub udp_timeout: Duration,
    pub inner_mtu: usize,
    /// Actor-bound reply queue: `(slot, wire-ready inner IP packet)`.
    pub inject_tx: mpsc::Sender<(usize, Bytes)>,
}

/// Per-flow pump: resolve → `dial_udp` → relay both directions until
/// idle expiry, a dead channel, or an outbound-session flush (the
/// TProxy `udp_flow` shape — the differences are the ConnType, the
/// hand-built reply packet, and the inject queue in place of a raw
/// socket reply).
pub(super) async fn run_flow(args: FlowArgs, mut rx: mpsc::Receiver<Bytes>) -> Result<(), String> {
    let FlowArgs {
        inner,
        in_name,
        in_port,
        slot,
        client,
        orig_dst,
        udp_timeout,
        inner_mtu,
        inject_tx,
    } = args;

    // The flow key and metadata dst are the ORIGINAL inner destination
    // — `pre_handle_metadata` may rewrite a fake-IP back to a hostname,
    // but the reply identity stays the address the client wrote to.
    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::WireGuard,
        src_ip: Some(client.ip()),
        src_port: client.port(),
        dst_ip: Some(orig_dst.ip()),
        dst_port: orig_dst.port(),
        in_name: in_name.as_ref().into(),
        in_port,
        ..Default::default()
    };

    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        meow_tunnel::PreHandleVerdict::Drop
    ) {
        return Err("unmapped fake-ip destination".into());
    }
    inner.pre_resolve(&mut metadata).await;
    inner.resolve_udp_dst(&mut metadata).await;
    let Some(dst_ip) = metadata.dst_ip else {
        return Err(format!(
            "dst_ip not resolved for {}",
            metadata.remote_address()
        ));
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);

    let Some(meow_tunnel::ResolvedTarget {
        adapter: proxy,
        rule_name,
        rule_payload,
        route: _route,
    }) = inner.resolve_proxy(&metadata).await
    else {
        return Err(format!(
            "no matching rule for {}",
            metadata.remote_address()
        ));
    };
    info!(
        "UDP {client} --> {orig_dst} match {} using {}",
        MatchedRule::new(&rule_name, &rule_payload, proxy.name()),
        UsingProxy::new(proxy.as_ref(), &metadata)
    );

    // Taken before the dial so a flush landing mid-dial still ends the
    // flow (issue #695): its socket may predate the new binding.
    let mut flush = inner.udp_flush_watch();
    let conn: Arc<dyn meow_common::ProxyPacketConn> = Arc::from(
        inner
            .dial_udp(proxy.as_ref(), &metadata)
            .await
            .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
    );
    drop(_route);

    // Dedicated reader: reads are never cancelled, so a stream-framed
    // conn can't lose a partially consumed frame (#514 pattern). The
    // reader hands raw reply payloads up; wrapping them as inner
    // packets happens in the flow loop below so the inject queue only
    // ever carries complete, MTU-checked datagrams.
    let (up_tx, mut up_rx) = mpsc::channel::<Bytes>(UDP_FLOW_QUEUE);
    let mut reply_task = tokio::spawn({
        let conn = Arc::clone(&conn);
        async move {
            let mut rbuf = vec![0u8; DATAGRAM_BUF];
            loop {
                match conn.read_packet(&mut rbuf).await {
                    Ok((n, _from)) => {
                        if up_tx
                            .send(Bytes::copy_from_slice(&rbuf[..n]))
                            .await
                            .is_err()
                        {
                            return Ok(()); // flow gone
                        }
                    }
                    Err(e) => return Err(format!("downstream read: {e}")),
                }
            }
        }
    });

    let idle = sleep_until(TokioInstant::now() + udp_timeout);
    tokio::pin!(idle);
    let result = loop {
        tokio::select! {
            () = &mut idle => break Ok(()),
            () = flush.flushed() => break Ok(()),
            queued = rx.recv() => match queued {
                Some(data) => {
                    // Drive write_packet in a nested select! so idle
                    // expiry, flush and a dead reader can cancel a
                    // blocked write (#893 pattern).
                    let write_result = tokio::select! {
                        () = &mut idle => break Ok(()),
                        () = flush.flushed() => break Ok(()),
                        done = &mut reply_task => break Err(match done {
                            Ok(Err(e)) => e,
                            Ok(Ok(())) => "downstream reader exited".into(),
                            Err(e) => format!("downstream reader task: {e}"),
                        }),
                        r = conn.write_packet(&data, &dst_addr) => r,
                    };
                    match write_result {
                        Ok(n) if n == data.len() => {
                            idle.as_mut().reset(TokioInstant::now() + udp_timeout);
                        }
                        Ok(n) => {
                            break Err(format!(
                                "upstream write {dst_addr}: short write {n}/{}",
                                data.len()
                            ));
                        }
                        Err(e) => {
                            break Err(format!("upstream write {dst_addr}: {e}"));
                        }
                    }
                }
                // Actor dropped the send half — shutdown or sweep.
                None => break Ok(()),
            },
            received = up_rx.recv() => match received {
                Some(data) => {
                    // The reply's inner identity is swapped: source =
                    // the address the client dialed, destination = the
                    // client. Oversize replies drop inside build_reply.
                    if let Some(pkt) = build_reply(orig_dst, client, &data, inner_mtu) {
                        match inject_tx.try_send((slot, pkt)) {
                            Ok(()) => idle.as_mut().reset(TokioInstant::now() + udp_timeout),
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                debug!("wg {in_name}: UDP reply inject queue full: dropping reply to {client}");
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break Ok(()),
                        }
                    }
                }
                None => break Err("downstream reader exited".into()),
            },
            done = &mut reply_task => break Err(match done {
                Ok(Err(e)) => e,
                Ok(Ok(())) => "downstream reader exited".into(),
                Err(e) => format!("downstream reader task: {e}"),
            }),
        }
    };

    // TProxy `udp_flow` cleanup (udp.rs:261): dropping the JoinHandle
    // would *detach* the reader — it stays parked on `conn.read_packet`
    // pinning the task, the conn's upstream session and its 64KiB
    // buffer until the remote happens to send again. Abort it and
    // close the conn so every exit path releases the flow fully.
    reply_task.abort();
    let _ = conn.close();
    result
}

/// Wrap `payload` in an inner UDP datagram `from` → `to` (both same
/// address family — the inner stack never mixes). `inner_mtu` is the
/// cap on the *whole IP packet*; an oversized reply is a silent drop
/// (`None`), never a fragment and never an ICMP error — spec §6.
pub(super) fn build_reply(
    from: SocketAddr,
    to: SocketAddr,
    payload: &[u8],
    inner_mtu: usize,
) -> Option<Bytes> {
    match (from.ip(), to.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            build_reply_v4(src, from.port(), dst, to.port(), payload, inner_mtu)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            build_reply_v6(src, from.port(), dst, to.port(), payload, inner_mtu)
        }
        _ => {
            // Unreachable: `client` and `orig_dst` are parsed from the
            // same inner packet's src/dst — always one family. The
            // debug_assert pins that flow-key contract; the drop stays
            // as the release-mode guard.
            debug_assert!(
                from.is_ipv4() == to.is_ipv4(),
                "inner UDP reply crossed address families ({from} → {to})"
            );
            debug!("wg: mixed-family UDP reply {from} → {to}; dropping");
            None
        }
    }
}

/// IPv4 header + UDP header + payload, checksums filled. Sizes: 20-byte
/// IPv4 header (no options) + 8-byte UDP header.
fn build_reply_v4(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    payload: &[u8],
    inner_mtu: usize,
) -> Option<Bytes> {
    const IP_HDR: usize = 20;
    const UDP_HDR: usize = 8;
    let total = IP_HDR + UDP_HDR + payload.len();
    if total > inner_mtu || total > u16::MAX as usize {
        return None;
    }
    let mut pkt = vec![0u8; total];
    // ── IPv4 header ───────────────────────────────────────────────
    pkt[0] = 0x45; // version 4, IHL 5 (20 bytes, no options)
    pkt[1] = 0; // DSCP/ECN
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    // identification 0, flags+offset 0 (DF clear), TTL 64, proto UDP
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    // checksum at [10..12] filled below
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    // ── UDP header ────────────────────────────────────────────────
    let udp_len = (UDP_HDR + payload.len()) as u16;
    pkt[IP_HDR..IP_HDR + 2].copy_from_slice(&sport.to_be_bytes());
    pkt[IP_HDR + 2..IP_HDR + 4].copy_from_slice(&dport.to_be_bytes());
    pkt[IP_HDR + 4..IP_HDR + 6].copy_from_slice(&udp_len.to_be_bytes());
    // UDP checksum at [IP_HDR+6..IP_HDR+8] filled below
    pkt[IP_HDR + UDP_HDR..].copy_from_slice(payload);

    // IPv4 header checksum over the header only.
    let ip_sum = ip_checksum(&pkt[..IP_HDR]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    // UDP checksum = pseudo-header + UDP header + payload.
    let udp_sum = udp_checksum_v4(&src, &dst, &pkt[IP_HDR..]);
    // 0x0000 is transmitted as 0xffff in IPv4 (zero means "no checksum",
    // and our reply always carries one — a computed zero is the RFC's
    // "transmitted as all ones" case).
    let udp_sum = if udp_sum == 0 { 0xffff } else { udp_sum };
    pkt[IP_HDR + 6..IP_HDR + 8].copy_from_slice(&udp_sum.to_be_bytes());
    Some(Bytes::from(pkt))
}

/// IPv6 header + UDP header + payload. Fixed 40-byte header; the UDP
/// checksum is *mandatory* on v6 (a zero field is an error, not
/// "checksum off"), so the pseudo-header sum is always computed.
fn build_reply_v6(
    src: Ipv6Addr,
    sport: u16,
    dst: Ipv6Addr,
    dport: u16,
    payload: &[u8],
    inner_mtu: usize,
) -> Option<Bytes> {
    const IP_HDR: usize = 40;
    const UDP_HDR: usize = 8;
    let udp_len = UDP_HDR + payload.len();
    let total = IP_HDR + udp_len;
    if total > inner_mtu || udp_len > u16::MAX as usize {
        return None;
    }
    let mut pkt = vec![0u8; total];
    // ── IPv6 header ───────────────────────────────────────────────
    pkt[0] = 0x60; // version 6, traffic class / flow label zero
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17; // next header: UDP
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    // ── UDP header ────────────────────────────────────────────────
    pkt[IP_HDR..IP_HDR + 2].copy_from_slice(&sport.to_be_bytes());
    pkt[IP_HDR + 2..IP_HDR + 4].copy_from_slice(&dport.to_be_bytes());
    pkt[IP_HDR + 4..IP_HDR + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[IP_HDR + UDP_HDR..].copy_from_slice(payload);

    // Mandatory UDP checksum over the v6 pseudo-header.
    let udp_sum = udp_checksum_v6(&src, &dst, &pkt[IP_HDR..]);
    let udp_sum = if udp_sum == 0 { 0xffff } else { udp_sum };
    pkt[IP_HDR + 6..IP_HDR + 8].copy_from_slice(&udp_sum.to_be_bytes());
    Some(Bytes::from(pkt))
}

/// RFC 1071 one's-complement checksum over `data` (odd tails pad a
/// zero byte into the sum's high half, per spec).
fn ip_checksum(data: &[u8]) -> u16 {
    !checksum_fold(data)
}

/// UDP checksum for an IPv4 datagram: the pseudo-header is
/// `src(4) | dst(4) | 0 | proto(17) | udp_len(2)` followed by the UDP
/// header (checksum field zero — the caller's buffer has it cleared)
/// and payload.
fn udp_checksum_v4(src: &Ipv4Addr, dst: &Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    let mut sum = checksum_fold(&pseudo);
    // Add the UDP datagram itself — checksum_fold restarts the carry
    // chain, so accumulate it folded in the same one's-complement space.
    sum = fold_add(sum, checksum_fold(udp));
    !sum
}

/// UDP checksum for IPv6: pseudo-header is
/// `src(16) | dst(16) | udp_len(4) | 0,0,0 | next_header(17)`.
fn udp_checksum_v6(src: &Ipv6Addr, dst: &Ipv6Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    let mut sum = checksum_fold(&pseudo);
    sum = fold_add(sum, checksum_fold(udp));
    !sum
}

/// Fold `data` into a 16-bit one's-complement partial sum (the
/// non-inverted accumulator every checksum above shares). `pub(crate)`
/// so the actor tests can build real checksummed segments for smoltcp.
pub(crate) fn checksum_fold(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum += u16::from_be_bytes(*w) as u32;
    }
    if let Some(&last) = rest.first() {
        sum += (last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// One's-complement addition of two folded partial sums.
fn fold_add(a: u16, b: u16) -> u16 {
    let mut sum = a as u32 + b as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec's golden vector: an IPv4 reply 10.0.0.1:53 →
    /// 10.0.0.2:5353 carrying `b"ab"` must serialize byte-for-byte.
    #[test]
    fn udp_reply_v4_golden() {
        let pkt = build_reply(
            "10.0.0.1:53".parse().unwrap(),
            "10.0.0.2:5353".parse().unwrap(),
            b"ab",
            1400,
        )
        .expect("reply builds");
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // IPv4: v4/IHL5, tos 0, len 30, id 0, frag 0, ttl 64, udp,
            // checksum 0x66cd, 10.0.0.1 → 10.0.0.2
            0x45, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x11, 0x66, 0xcd, 0x0a, 0x00, 0x00, 0x01,
            0x0a, 0x00, 0x00, 0x02,
            // UDP: 53 → 5353, len 10, checksum 0x7557
            0x00, 0x35, 0x14, 0xe9, 0x00, 0x0a, 0x75, 0x57,
            b'a', b'b',
        ];
        assert_eq!(&pkt[..], expected);
    }

    /// The v6 golden: fd00::1:53 → fd00::2:5353 with `b"ab"` — the
    /// mandatory UDP checksum is the field most hand-rolled builders
    /// get wrong.
    #[test]
    fn udp_reply_v6_golden() {
        let pkt = build_reply(
            "[fd00::1]:53".parse().unwrap(),
            "[fd00::2]:5353".parse().unwrap(),
            b"ab",
            1400,
        )
        .expect("reply builds");
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // IPv6: v6, len 10, next=UDP, hop 64, fd00::1 → fd00::2
            0x60, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x11, 0x40,
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            // UDP: 53 → 5353, len 10, checksum 0x8f55
            0x00, 0x35, 0x14, 0xe9, 0x00, 0x0a, 0x8f, 0x55,
            b'a', b'b',
        ];
        assert_eq!(&pkt[..], expected);
    }

    /// The checksums the goldens pin must also *verify*: run the
    /// receiver-side checksum over each built datagram.
    #[test]
    fn checksums_verify() {
        let v4 = build_reply(
            "192.0.2.1:8080".parse().unwrap(),
            "192.0.2.2:9090".parse().unwrap(),
            b"hello, wireguard",
            1400,
        )
        .unwrap();
        // IPv4 header checksum verifies to 0xffff-fold → sum of header
        // words incl. checksum == 0.
        assert_eq!(checksum_fold(&v4[..20]), 0xffff);

        let v6 = build_reply(
            "[2001:db8::1]:1234".parse().unwrap(),
            "[2001:db8::2]:4321".parse().unwrap(),
            b"\x00\x01\x02\x03",
            1400,
        )
        .unwrap();
        let udp = &v6[40..];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&v6[8..24]);
        pseudo.extend_from_slice(&v6[24..40]);
        pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        let sum = fold_add(checksum_fold(&pseudo), checksum_fold(udp));
        assert_eq!(sum, 0xffff);
    }

    /// An oversized payload produces no packet at all — and nothing is
    /// emitted on the wire (the caller drops `None` silently; there is
    /// deliberately no ICMP fragmentation-needed).
    #[test]
    fn oversized_reply_drops() {
        let payload = vec![0u8; 2000];
        assert!(build_reply(
            "10.0.0.1:53".parse().unwrap(),
            "10.0.0.2:5353".parse().unwrap(),
            &payload,
            1400,
        )
        .is_none());
        assert!(build_reply(
            "[fd00::1]:53".parse().unwrap(),
            "[fd00::2]:5353".parse().unwrap(),
            &payload,
            1400,
        )
        .is_none());
    }

    /// Exactly-at-MTU replies still build — the bound is inclusive.
    #[test]
    fn mtu_boundary_inclusive() {
        // v4: 20 + 8 + payload == mtu → ok.
        let payload = vec![0u8; 1400 - 28];
        assert!(build_reply(
            "10.0.0.1:53".parse().unwrap(),
            "10.0.0.2:5353".parse().unwrap(),
            &payload,
            1400,
        )
        .is_some());
    }
}
