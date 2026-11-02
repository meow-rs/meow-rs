//! `tun.stack: system`: the device's TCP is terminated by the
//! host kernel instead of lwIP, the way mihomo's and sing-box's system
//! stack does it.
//!
//! The device carries address A (`inet4-address`, plus `inet6-address`) and
//! a kernel `TcpListener` on A. A second address of the device's subnet, B,
//! is the NAT peer. The packet pump rewrites in place, without copying:
//!
//! ```text
//! client C:c → D:d      read from the device  ⇒  B:n → A:l   written back
//! kernel A:l → B:n      read from the device  ⇒  D:d → C:c   written back
//! ```
//!
//! so the kernel sees an ordinary inbound connection from B:n, accepts it,
//! and the accept loop finds C:c → D:d again by the NAT port n. Only the
//! addresses, ports and checksums change (RFC 1624 incremental updates).
//! The accepted socket is a plain `TcpStream`: the kernel does the TCP work
//! (segmentation, ACKs, retransmits, window scaling) and a DIRECT relay
//! splices it. UDP, ICMP and anything that is not plain TCP go to lwIP.
//!
//! A NAT entry is made by the client's SYN and lives until the flow's
//! handler ends (then [`CLOSING_TTL`] for the FIN/ACK tail), or for
//! [`PENDING_TTL`] if the handshake never completes.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};

use super::udp::TunNets;

/// A SYN whose handshake never completed (the kernel never accepted it).
const PENDING_TTL: Duration = Duration::from_secs(30);
/// After the handler ends: room for the FIN/ACK exchange and retransmits.
const CLOSING_TTL: Duration = Duration::from_secs(30);
/// How often expired entries are swept.
pub(super) const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// NAT ports handed out, cycled through; 55 536 concurrent flows.
const PORT_FIRST: u16 = 10_000;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// What the pump does with a packet after [`Nat::translate`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Rewritten in place: write it back to the device.
    Write,
    /// Not for anyone (unknown flow, loop): drop it.
    Drop,
    /// Not TCP the NAT handles: hand it to lwIP unchanged.
    Stack,
}

#[derive(Clone, Copy, Debug)]
enum State {
    Pending(Instant),
    Open,
    Closing(Instant),
}

struct Entry {
    client: SocketAddr,
    dst: SocketAddr,
    state: State,
}

#[derive(Default)]
struct Table {
    by_flow: HashMap<(SocketAddr, SocketAddr), u16>,
    by_port: HashMap<u16, Entry>,
    next: u16,
}

impl Table {
    fn alloc(&mut self, client: SocketAddr, dst: SocketAddr, now: Instant) -> Option<u16> {
        if self.by_port.len() > usize::from(u16::MAX - PORT_FIRST) {
            return None;
        }
        loop {
            let port = self.next.max(PORT_FIRST);
            self.next = port.wrapping_add(1);
            if let std::collections::hash_map::Entry::Vacant(slot) = self.by_port.entry(port) {
                slot.insert(Entry {
                    client,
                    dst,
                    state: State::Pending(now),
                });
                self.by_flow.insert((client, dst), port);
                return Some(port);
            }
        }
    }

    fn remove(&mut self, port: u16) {
        if let Some(e) = self.by_port.remove(&port) {
            let key = (e.client, e.dst);
            if self.by_flow.get(&key) == Some(&port) {
                self.by_flow.remove(&key);
            }
        }
    }
}

/// The NAT's own addresses: A (device, listener) and B (peer) per family.
#[derive(Clone, Copy, Debug)]
pub(super) struct NatAddrs {
    pub a4: Ipv4Addr,
    pub b4: Ipv4Addr,
    pub port4: u16,
    pub v6: Option<(Ipv6Addr, Ipv6Addr, u16)>,
}

pub(super) struct Nat {
    addrs: NatAddrs,
    nets: TunNets,
    table: Mutex<Table>,
}

impl Nat {
    pub(super) fn new(addrs: NatAddrs, nets: TunNets) -> Self {
        Self {
            addrs,
            nets,
            table: Mutex::new(Table::default()),
        }
    }

    /// Rewrite a packet read from the device in place.
    pub(super) fn translate(&self, pkt: &mut [u8]) -> Verdict {
        match pkt.first().map(|b| b >> 4) {
            Some(4) => self.translate_v4(pkt),
            Some(6) => self.translate_v6(pkt),
            _ => Verdict::Stack,
        }
    }

    fn translate_v4(&self, pkt: &mut [u8]) -> Verdict {
        if pkt.len() < 20 || pkt[9] != 6 {
            return Verdict::Stack;
        }
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        if ihl < 20 || pkt.len() < ihl + 20 {
            return Verdict::Drop;
        }
        // Fragments (MF or an offset) carry no ports to translate.
        if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0 {
            return Verdict::Drop;
        }
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let tcp = &pkt[ihl..];
        let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
        let flags = tcp[13];
        let a = self.addrs;

        let (new_src, new_dst) = if src == a.a4 && sport == a.port4 {
            if dst != a.b4 {
                return Verdict::Drop;
            }
            match self.reply_target(dport) {
                Some((SocketAddr::V4(orig_dst), SocketAddr::V4(client))) => (orig_dst, client),
                _ => return Verdict::Drop,
            }
        } else {
            if self.nets.v4.contains(&dst) {
                return Verdict::Drop;
            }
            let client = SocketAddr::V4(SocketAddrV4::new(src, sport));
            let target = SocketAddr::V4(SocketAddrV4::new(dst, dport));
            let Some(port) = self.forward_port(client, target, flags) else {
                return Verdict::Drop;
            };
            (
                SocketAddrV4::new(a.b4, port),
                SocketAddrV4::new(a.a4, a.port4),
            )
        };

        let mut addrs = [0u8; 8];
        addrs[..4].copy_from_slice(&new_src.ip().octets());
        addrs[4..].copy_from_slice(&new_dst.ip().octets());
        let ip_check = csum_adjust(read16(pkt, 10), &pkt[12..20], &addrs);
        write16(pkt, 10, ip_check);
        rewrite_tcp(pkt, ihl, 12..20, &addrs, new_src.port(), new_dst.port());
        pkt[12..20].copy_from_slice(&addrs);
        Verdict::Write
    }

    fn translate_v6(&self, pkt: &mut [u8]) -> Verdict {
        // Extension headers before TCP are left to lwIP.
        if pkt.len() < 40 || pkt[6] != 6 {
            return Verdict::Stack;
        }
        let Some((a6, b6, port6)) = self.addrs.v6 else {
            return Verdict::Stack;
        };
        if pkt.len() < 60 {
            return Verdict::Drop;
        }
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap_or_default());
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap_or_default());
        let sport = read16(pkt, 40);
        let dport = read16(pkt, 42);
        let flags = pkt[40 + 13];

        let (new_src, new_dst) = if src == a6 && sport == port6 {
            if dst != b6 {
                return Verdict::Drop;
            }
            match self.reply_target(dport) {
                Some((SocketAddr::V6(orig_dst), SocketAddr::V6(client))) => (orig_dst, client),
                _ => return Verdict::Drop,
            }
        } else {
            if self.nets.v6.is_some_and(|net| net.contains(&dst)) {
                return Verdict::Drop;
            }
            let client = SocketAddr::V6(SocketAddrV6::new(src, sport, 0, 0));
            let target = SocketAddr::V6(SocketAddrV6::new(dst, dport, 0, 0));
            let Some(port) = self.forward_port(client, target, flags) else {
                return Verdict::Drop;
            };
            (
                SocketAddrV6::new(b6, port, 0, 0),
                SocketAddrV6::new(a6, port6, 0, 0),
            )
        };

        let mut addrs = [0u8; 32];
        addrs[..16].copy_from_slice(&new_src.ip().octets());
        addrs[16..].copy_from_slice(&new_dst.ip().octets());
        rewrite_tcp(pkt, 40, 8..40, &addrs, new_src.port(), new_dst.port());
        pkt[8..40].copy_from_slice(&addrs);
        Verdict::Write
    }

    /// The client's flow → its NAT port; a bare SYN opens an entry (or a
    /// fresh one over a closing flow that reuses the 4-tuple).
    fn forward_port(&self, client: SocketAddr, dst: SocketAddr, flags: u8) -> Option<u16> {
        let syn = flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN) == TCP_SYN;
        let mut t = self.table.lock();
        if let Some(&port) = t.by_flow.get(&(client, dst)) {
            let closing = matches!(
                t.by_port.get(&port).map(|e| e.state),
                Some(State::Closing(_))
            );
            if !(syn && closing) {
                return Some(port);
            }
        }
        if syn {
            t.alloc(client, dst, Instant::now())
        } else {
            None
        }
    }

    /// The (original destination, client) a kernel reply to `port` goes
    /// back as.
    fn reply_target(&self, port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let t = self.table.lock();
        t.by_port.get(&port).map(|e| (e.dst, e.client))
    }

    /// The kernel accepted a connection from `peer` (B:n): mark the entry
    /// open and return (client, original destination).
    pub(super) fn accepted(&self, peer: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
        let b_matches = match peer {
            SocketAddr::V4(p) => *p.ip() == self.addrs.b4,
            SocketAddr::V6(p) => self.addrs.v6.is_some_and(|(_, b6, _)| *p.ip() == b6),
        };
        if !b_matches {
            return None;
        }
        let mut t = self.table.lock();
        let e = t.by_port.get_mut(&peer.port())?;
        e.state = State::Open;
        Some((e.client, e.dst))
    }

    /// The flow's handler ended.
    pub(super) fn closed(&self, port: u16) {
        if let Some(e) = self.table.lock().by_port.get_mut(&port) {
            e.state = State::Closing(Instant::now());
        }
    }

    pub(super) fn sweep(&self) {
        let now = Instant::now();
        let mut t = self.table.lock();
        let expired: Vec<u16> = t
            .by_port
            .iter()
            .filter(|(_, e)| match e.state {
                State::Pending(at) => now.duration_since(at) > PENDING_TTL,
                State::Closing(at) => now.duration_since(at) > CLOSING_TTL,
                State::Open => false,
            })
            .map(|(&port, _)| port)
            .collect();
        for port in expired {
            t.remove(port);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.table.lock().by_port.len()
    }
}

/// Marks the flow's NAT entry closing when its handler ends, however it
/// ends (finished, failed, aborted).
pub(super) struct FlowGuard {
    pub nat: Arc<Nat>,
    pub port: u16,
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.nat.closed(self.port);
    }
}

/// The kernel side: the NAT plus its listeners on A.
pub(super) struct SystemStack {
    pub nat: Arc<Nat>,
    pub v4: TcpListener,
    pub v6: Option<TcpListener>,
}

impl SystemStack {
    /// Bind the listeners on the device's addresses (the device must be up
    /// with them assigned) and pick the NAT peers. Fails when the IPv4
    /// subnet has no second host address (a /31 or /32).
    pub(super) async fn bind(
        nets: TunNets,
        a4: Ipv4Addr,
        a6: Option<Ipv6Addr>,
    ) -> io::Result<Self> {
        let b4 = nets.v4.hosts().find(|h| *h != a4).ok_or_else(|| {
            io::Error::other(format!(
                "inet4-address {} leaves no second host address for the NAT peer \
                 (use a /30 or wider)",
                nets.v4
            ))
        })?;
        let v4 = TcpListener::bind(SocketAddr::from((a4, 0))).await?;
        let port4 = v4.local_addr()?.port();

        let mut v6 = None;
        let mut v6_addrs = None;
        if let (Some(a6), Some(net6)) = (a6, nets.v6) {
            // The subnet-router anycast address (all-zero host part) is
            // not a usable peer.
            let b6 = net6.hosts().skip(1).find(|h| *h != a6);
            match b6 {
                Some(b6) => match TcpListener::bind(SocketAddr::from((a6, 0))).await {
                    Ok(l) => {
                        v6_addrs = Some((a6, b6, l.local_addr()?.port()));
                        v6 = Some(l);
                    }
                    Err(e) => tracing::warn!(
                        "tun system stack: IPv6 listener on {a6} failed ({e}); \
                         IPv6 TCP stays on lwIP"
                    ),
                },
                None => tracing::warn!(
                    "tun system stack: inet6-address {net6} has no second host address; \
                     IPv6 TCP stays on lwIP"
                ),
            }
        }

        let addrs = NatAddrs {
            a4,
            b4,
            port4,
            v6: v6_addrs,
        };
        Ok(Self {
            nat: Arc::new(Nat::new(addrs, nets)),
            v4,
            v6,
        })
    }

    /// Accept the next kernel connection: (stream, client, original
    /// destination, its NAT guard). Connections no NAT entry knows are
    /// dropped here.
    pub(super) async fn accept(
        &self,
    ) -> io::Result<(TcpStream, SocketAddr, SocketAddr, FlowGuard)> {
        loop {
            let (stream, peer) = match &self.v6 {
                Some(v6) => tokio::select! {
                    r = self.v4.accept() => r?,
                    r = v6.accept() => r?,
                },
                None => self.v4.accept().await?,
            };
            if let Some((client, dst)) = self.nat.accepted(peer) {
                let guard = FlowGuard {
                    nat: Arc::clone(&self.nat),
                    port: peer.port(),
                };
                return Ok((stream, client, dst, guard));
            }
            tracing::debug!("tun system stack: dropping connection from unknown peer {peer}");
        }
    }
}

fn read16(pkt: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([pkt[at], pkt[at + 1]])
}

fn write16(pkt: &mut [u8], at: usize, v: u16) {
    pkt[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// Rewrite the TCP ports at `tcp_off` and fix the TCP checksum for them and
/// for the pseudo-header addresses at `addr_range` becoming `new_addrs`.
fn rewrite_tcp(
    pkt: &mut [u8],
    tcp_off: usize,
    addr_range: std::ops::Range<usize>,
    new_addrs: &[u8],
    sport: u16,
    dport: u16,
) {
    let mut ports = [0u8; 4];
    ports[..2].copy_from_slice(&sport.to_be_bytes());
    ports[2..].copy_from_slice(&dport.to_be_bytes());
    let check_at = tcp_off + 16;
    let mut check = csum_adjust(read16(pkt, check_at), &pkt[addr_range], new_addrs);
    check = csum_adjust(check, &pkt[tcp_off..tcp_off + 4], &ports);
    write16(pkt, check_at, check);
    pkt[tcp_off..tcp_off + 4].copy_from_slice(&ports);
}

/// RFC 1624 eq. 3: `HC' = ~(~HC + ~m + m')` over 16-bit words. `old` and
/// `new` are equally long, even, and word-aligned in the checksummed data.
fn csum_adjust(check: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = u32::from(!check);
    for w in old.as_chunks::<2>().0 {
        sum += u32::from(!u16::from_be_bytes([w[0], w[1]]));
    }
    for w in new.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation, reason = "folded to 16 bits above")]
    let folded = sum as u16;
    !folded
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::{Ipv4Net, Ipv6Net};

    fn ones_complement_sum(data: &[u8], mut sum: u32) -> u32 {
        for w in data.chunks(2) {
            let hi = u32::from(w[0]) << 8;
            let lo = w.get(1).map_or(0, |b| u32::from(*b));
            sum += hi | lo;
        }
        sum
    }

    fn fold(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Full TCP checksum over the pseudo-header and segment (check field
    /// zeroed first).
    fn tcp_check(pkt: &[u8]) -> u16 {
        let (pseudo, seg) = if pkt[0] >> 4 == 4 {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            let seg = &pkt[ihl..];
            let mut p = pkt[12..20].to_vec();
            p.extend_from_slice(&[0, 6]);
            p.extend_from_slice(&(seg.len() as u16).to_be_bytes());
            (p, seg)
        } else {
            let seg = &pkt[40..];
            let mut p = pkt[8..40].to_vec();
            p.extend_from_slice(&(seg.len() as u32).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 6]);
            (p, seg)
        };
        let mut seg = seg.to_vec();
        seg[16] = 0;
        seg[17] = 0;
        fold(ones_complement_sum(&seg, ones_complement_sum(&pseudo, 0)))
    }

    fn ip_check(pkt: &[u8]) -> u16 {
        let mut h = pkt[..20].to_vec();
        h[10] = 0;
        h[11] = 0;
        fold(ones_complement_sum(&h, 0))
    }

    fn v4_packet(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
        let payload = b"hello, odd payload";
        let total = 20 + 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&7u32.to_be_bytes());
        p[32] = 0x50;
        p[33] = flags;
        p[34..36].copy_from_slice(&64240u16.to_be_bytes());
        p[40..].copy_from_slice(payload);
        let c = ip_check(&p);
        write16(&mut p, 10, c);
        let c = tcp_check(&p);
        write16(&mut p, 36, c);
        p
    }

    fn v6_packet(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, flags: u8) -> Vec<u8> {
        let payload = b"abc";
        let mut p = vec![0u8; 40 + 20 + payload.len()];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p[6] = 6;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40..42].copy_from_slice(&sport.to_be_bytes());
        p[42..44].copy_from_slice(&dport.to_be_bytes());
        p[52] = 0x50;
        p[53] = flags;
        p[60..].copy_from_slice(payload);
        let c = tcp_check(&p);
        write16(&mut p, 56, c);
        p
    }

    fn nat() -> Nat {
        let a6: Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let b6: Ipv6Addr = "fdfe:dcba:9876::2".parse().unwrap();
        Nat::new(
            NatAddrs {
                a4: Ipv4Addr::new(172, 31, 0, 1),
                b4: Ipv4Addr::new(172, 31, 0, 2),
                port4: 40000,
                v6: Some((a6, b6, 40001)),
            },
            TunNets {
                v4: "172.31.0.1/30".parse::<Ipv4Net>().unwrap(),
                v6: Some("fdfe:dcba:9876::1/126".parse::<Ipv6Net>().unwrap()),
            },
        )
    }

    fn addr4(p: &[u8], at: usize) -> SocketAddr {
        SocketAddr::from((
            Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3]),
            read16(p, if at == 12 { 20 } else { 22 }),
        ))
    }

    #[test]
    fn v4_round_trip_keeps_checksums_valid() {
        let nat = nat();
        let mut syn = v4_packet([192, 168, 1, 10], 51000, [1, 1, 1, 1], 443, TCP_SYN);
        assert_eq!(nat.translate(&mut syn), Verdict::Write);
        assert_eq!(addr4(&syn, 16), "172.31.0.1:40000".parse().unwrap());
        let peer = addr4(&syn, 12);
        assert_eq!(
            peer.ip(),
            std::net::IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2))
        );
        assert_eq!(read16(&syn, 10), ip_check(&syn), "IP header checksum");
        assert_eq!(read16(&syn, 36), tcp_check(&syn), "TCP checksum");

        // The kernel's SYN-ACK back to the NAT peer.
        let mut reply = v4_packet(
            [172, 31, 0, 1],
            40000,
            [172, 31, 0, 2],
            peer.port(),
            TCP_SYN | TCP_ACK,
        );
        assert_eq!(nat.translate(&mut reply), Verdict::Write);
        assert_eq!(addr4(&reply, 12), "1.1.1.1:443".parse().unwrap());
        assert_eq!(addr4(&reply, 16), "192.168.1.10:51000".parse().unwrap());
        assert_eq!(read16(&reply, 10), ip_check(&reply));
        assert_eq!(read16(&reply, 36), tcp_check(&reply));

        // The client's next segment reuses the entry.
        let mut ack = v4_packet([192, 168, 1, 10], 51000, [1, 1, 1, 1], 443, TCP_ACK);
        assert_eq!(nat.translate(&mut ack), Verdict::Write);
        assert_eq!(addr4(&ack, 12), peer);

        assert_eq!(
            nat.accepted(peer),
            Some((
                "192.168.1.10:51000".parse().unwrap(),
                "1.1.1.1:443".parse().unwrap()
            ))
        );
    }

    #[test]
    fn v6_round_trip_keeps_checksum_valid() {
        let nat = nat();
        let c: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let d: Ipv6Addr = "2606:4700::1111".parse().unwrap();
        let mut syn = v6_packet(c, 40500, d, 443, TCP_SYN);
        assert_eq!(nat.translate(&mut syn), Verdict::Write);
        assert_eq!(read16(&syn, 56), tcp_check(&syn));
        let port = read16(&syn, 40);
        let a6: Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let b6: Ipv6Addr = "fdfe:dcba:9876::2".parse().unwrap();
        let mut reply = v6_packet(a6, 40001, b6, port, TCP_SYN | TCP_ACK);
        assert_eq!(nat.translate(&mut reply), Verdict::Write);
        assert_eq!(&reply[8..24], &d.octets());
        assert_eq!(&reply[24..40], &c.octets());
        assert_eq!(read16(&reply, 40), 443);
        assert_eq!(read16(&reply, 42), 40500);
        assert_eq!(read16(&reply, 56), tcp_check(&reply));
    }

    #[test]
    fn unknown_flows_loops_and_non_tcp() {
        let nat = nat();
        // A mid-flow segment nobody opened.
        let mut ack = v4_packet([192, 168, 1, 10], 1, [1, 1, 1, 1], 443, TCP_ACK);
        assert_eq!(nat.translate(&mut ack), Verdict::Drop);
        // A reply to a NAT port with no entry.
        let mut reply = v4_packet([172, 31, 0, 1], 40000, [172, 31, 0, 2], 12345, TCP_ACK);
        assert_eq!(nat.translate(&mut reply), Verdict::Drop);
        // Into the device's own subnet: would loop.
        let mut lp = v4_packet([192, 168, 1, 10], 2, [172, 31, 0, 3], 80, TCP_SYN);
        assert_eq!(nat.translate(&mut lp), Verdict::Drop);
        // UDP goes to lwIP untouched.
        let mut udp = v4_packet([192, 168, 1, 10], 3, [1, 1, 1, 1], 53, 0);
        udp[9] = 17;
        let before = udp.clone();
        assert_eq!(nat.translate(&mut udp), Verdict::Stack);
        assert_eq!(udp, before);
        assert_eq!(nat.len(), 0);
    }

    #[test]
    fn entries_expire_and_closing_flows_get_a_fresh_port() {
        let nat = nat();
        let mut syn = v4_packet([10, 0, 0, 5], 5000, [8, 8, 8, 8], 80, TCP_SYN);
        nat.translate(&mut syn);
        let first = read16(&syn, 20);
        let peer = SocketAddr::from((Ipv4Addr::new(172, 31, 0, 2), first));
        assert!(nat.accepted(peer).is_some());
        nat.closed(first);
        // A new SYN on the same 4-tuple while the old one closes.
        let mut syn2 = v4_packet([10, 0, 0, 5], 5000, [8, 8, 8, 8], 80, TCP_SYN);
        nat.translate(&mut syn2);
        let second = read16(&syn2, 20);
        assert_ne!(first, second);
        assert_eq!(nat.len(), 2);
        // Age both past their TTLs.
        {
            let mut t = nat.table.lock();
            let old = Instant::now() - PENDING_TTL - Duration::from_secs(1);
            t.by_port.get_mut(&first).unwrap().state = State::Closing(old);
            t.by_port.get_mut(&second).unwrap().state = State::Pending(old);
        }
        nat.sweep();
        assert_eq!(nat.len(), 0);
        assert!(nat.table.lock().by_flow.is_empty());
    }

    #[test]
    fn csum_adjust_matches_rfc1624_example() {
        // RFC 1624 §4: HC = 0xDD2F, m = 0x5555 → m' = 0x3285 gives 0x0000.
        assert_eq!(csum_adjust(0xDD2F, &[0x55, 0x55], &[0x32, 0x85]), 0x0000);
    }
}
