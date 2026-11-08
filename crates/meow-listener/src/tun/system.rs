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
//! splices it. UDP is parsed off the device by the pump
//! (`direct_udp.rs`); ICMP, UDP fragments and IPv6 extension headers go
//! to lwIP, and TCP fragments are dropped (lwIP would reassemble a flow
//! the kernel owns and reset it).
//!
//! A NAT entry is made by the client's SYN and lives until the flow's
//! handler ends (then [`CLOSING_TTL`] for the FIN/ACK tail), or for
//! [`PENDING_TTL`] if the handshake never completes.

use std::collections::{HashMap, VecDeque};
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
/// Half-open entries allowed at once: a port scan of IP literals must not
/// take the port space from established flows. At the cap the oldest
/// pending entry is evicted to admit a new SYN — the UDP flow table's
/// `MAX_FLOWS` convention — rather than refusing every fresh SYN until an
/// entry's [`PENDING_TTL`] runs out.
const PENDING_MAX: usize = 4096;

const IPV6_FRAGMENT: u8 = 44;
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
    /// Ports of pending entries, oldest first, with the alloc timestamp —
    /// eviction order at `PENDING_MAX`. Slots whose entry left `Pending`
    /// (opened, closed, swept) are stale: the eviction walk skips them
    /// and the periodic sweep drops them.
    pending_order: VecDeque<(u16, Instant)>,
    next: u16,
    pending: usize,
}

impl Table {
    fn alloc(&mut self, client: SocketAddr, dst: SocketAddr, now: Instant) -> Option<u16> {
        if self.by_port.len() > usize::from(u16::MAX - PORT_FIRST) {
            return None;
        }
        // At the half-open cap, evict the oldest pending entry rather than
        // refusing the SYN: under a scan flood, hard-dropping meant every
        // legitimate handshake queued behind a full 30 s TTL. The oldest
        // pending is the likeliest garbage — a real handshake completes
        // long before it would be evicted under anything but a flood.
        if self.pending >= PENDING_MAX && !self.evict_oldest_pending() {
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
                self.pending += 1;
                self.pending_order.push_back((port, now));
                self.by_flow.insert((client, dst), port);
                return Some(port);
            }
        }
    }

    /// Remove the oldest still-pending entry; stale deque slots (opened,
    /// closed, swept, or the port re-allocated to a newer pending) are
    /// skipped. `false` only when nothing pending remains.
    fn evict_oldest_pending(&mut self) -> bool {
        while let Some((port, at)) = self.pending_order.pop_front() {
            if matches!(
                self.by_port.get(&port).map(|e| e.state),
                Some(State::Pending(t)) if t == at
            ) {
                self.remove(port);
                return true;
            }
        }
        false
    }

    fn remove(&mut self, port: u16) {
        if let Some(e) = self.by_port.remove(&port) {
            if matches!(e.state, State::Pending(_)) {
                self.pending -= 1;
            }
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

impl NatAddrs {
    /// Whether `ip` is one of the NAT's peer addresses (B4 or B6) —
    /// assigned to nothing, so nothing can legitimately source packets
    /// from it (the trust-boundary comment in `translate_v4`).
    pub(super) fn is_peer(&self, ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => v4 == self.b4,
            std::net::IpAddr::V6(v6) => self.v6.is_some_and(|(_, b6, _)| v6 == b6),
        }
    }
}

pub(super) struct Nat {
    pub(super) addrs: NatAddrs,
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

    /// Rewrite a packet read from the device in place. `partial`: its TCP
    /// checksum is a virtio `NEEDS_CSUM` one (the field holds only the
    /// pseudo-header sum; whoever receives the packet sums the segment).
    pub(super) fn translate(&self, pkt: &mut [u8], partial: bool) -> Verdict {
        match pkt.first().map(|b| b >> 4) {
            Some(4) => self.translate_v4(pkt, partial),
            Some(6) => self.translate_v6(pkt, partial),
            _ => Verdict::Stack,
        }
    }

    fn translate_v4(&self, pkt: &mut [u8], partial: bool) -> Verdict {
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

        // `src == A && sport == port4` does not alone prove a kernel
        // reply: A is an ordinary client source (see below), and its
        // `port4` can sit on a host socket — bound before the listener
        // was, or held across a netns boundary — so a dial `A:port4 →
        // D:d` exists and must take the client arm like any other
        // A-source rather than be dropped. What proves the reply is the
        // peer: the kernel's listener only ever talks to B.
        let (new_src, new_dst) = if src == a.a4 && sport == a.port4 && dst == a.b4 {
            match self.reply_target(dport) {
                Some((SocketAddr::V4(orig_dst), SocketAddr::V4(client))) => (orig_dst, client),
                _ => return Verdict::Drop,
            }
        } else {
            // Trust boundary: B is the NAT's own peer address — it is
            // assigned to nothing, so nothing can legitimately source
            // packets from it, and a forged one (a LAN peer forwarded in
            // under loose rp_filter) must not mint a NAT entry. A is not
            // checked the same way: the host's own unsourced sockets take
            // the device address, so A is *the* ordinary client source —
            // forged A-sourced packets are indistinguishable from real
            // host flows, which is the kernel's martian filtering's job.
            if src == a.b4 {
                return Verdict::Drop;
            }
            if super::udp::is_looping_dst(std::net::IpAddr::V4(dst), self.nets) {
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
        rewrite_tcp(
            pkt,
            ihl,
            12..20,
            &addrs,
            new_src.port(),
            new_dst.port(),
            partial,
        );
        pkt[12..20].copy_from_slice(&addrs);
        Verdict::Write
    }

    fn translate_v6(&self, pkt: &mut [u8], partial: bool) -> Verdict {
        // TCP fragments are dropped as on IPv4: lwIP would reassemble them
        // into a flow the kernel owns and reset it. The extension-header
        // chain is walked — a Fragment behind Hop-by-Hop/Routing/etc.
        // counts the same as a first-header one.
        if v6_tcp_fragment(pkt) {
            return Verdict::Drop;
        }
        // Other extension headers before TCP are left to lwIP.
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

        // As on IPv4: a reply always aims at the NAT peer, so `dst ==
        // b6` is part of the match — anything else from `a6:port6` is a
        // client flow whose source port collided with the listener's.
        let (new_src, new_dst) = if src == a6 && sport == port6 && dst == b6 {
            match self.reply_target(dport) {
                Some((SocketAddr::V6(orig_dst), SocketAddr::V6(client))) => (orig_dst, client),
                _ => return Verdict::Drop,
            }
        } else {
            // As on IPv4: the NAT peer b6 is never a client source.
            if src == b6 {
                return Verdict::Drop;
            }
            if super::udp::is_looping_dst(std::net::IpAddr::V6(dst), self.nets) {
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
        rewrite_tcp(
            pkt,
            40,
            8..40,
            &addrs,
            new_src.port(),
            new_dst.port(),
            partial,
        );
        pkt[8..40].copy_from_slice(&addrs);
        Verdict::Write
    }

    /// The client's flow → its NAT port; a bare SYN opens an entry (or a
    /// fresh one over a closing flow that reuses the 4-tuple).
    fn forward_port(&self, client: SocketAddr, dst: SocketAddr, flags: u8) -> Option<u16> {
        let syn = flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN) == TCP_SYN;
        let mut t = self.table.lock();
        if let Some(&port) = t.by_flow.get(&(client, dst)) {
            // A non-SYN packet on a known flow — the common case — needs
            // no `by_port` probe: only a SYN may reopen a closing entry.
            if !syn
                || !matches!(
                    t.by_port.get(&port).map(|e| e.state),
                    Some(State::Closing(_))
                )
            {
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
        if !self.addrs.is_peer(peer.ip()) {
            return None;
        }
        let mut t = self.table.lock();
        let e = t.by_port.get_mut(&peer.port())?;
        let was_pending = matches!(e.state, State::Pending(_));
        e.state = State::Open;
        let flow = (e.client, e.dst);
        if was_pending {
            t.pending -= 1;
        }
        Some(flow)
    }

    /// The flow's handler ended.
    pub(super) fn closed(&self, port: u16) {
        let mut t = self.table.lock();
        if let Some(e) = t.by_port.get_mut(&port) {
            let was_pending = matches!(e.state, State::Pending(_));
            e.state = State::Closing(Instant::now());
            if was_pending {
                t.pending -= 1;
            }
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
        // `pending_order` also accrues stale slots when an entry opens,
        // closes, or ages out — the eviction walk only consumes them at
        // the cap. Drop them here so the deque tracks live entries plus
        // at most one sweep interval's churn.
        let Table {
            by_port,
            pending_order,
            ..
        } = &mut *t;
        pending_order.retain(|(port, at)| {
            matches!(
                by_port.get(port).map(|e| e.state),
                Some(State::Pending(s)) if s == *at
            )
        });
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
                 (use a /31 or wider)",
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
                // Small writes go out at once, as lwIP sends them.
                let _ = stream.set_nodelay(true);
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

/// Whether an IPv6 packet is a TCP fragment: its extension-header chain
/// holds a Fragment header whose next-header is TCP. Only the
/// unfragmentable part (headers before the Fragment) is walked — the
/// Fragment's own next-header field names the payload protocol in every
/// fragment of a datagram, so the answer never needs to read fragment
/// payload bytes. `false` for a malformed or unfinished chain (lwIP
/// decides on those) and for anything without a Fragment header.
fn v6_tcp_fragment(pkt: &[u8]) -> bool {
    const MAX_EXT_CHAIN: usize = 8;
    let Some(&nh0) = pkt.get(6) else {
        return false;
    };
    let mut nh = nh0;
    // First byte past the fixed 40-byte IPv6 header.
    let mut off = 40usize;
    for _ in 0..MAX_EXT_CHAIN {
        // Extension headers with a (next-header, hdr-ext-len) layout
        // measured in 8-octet units, not counting the first: Hop-by-Hop,
        // Routing, Destination Options, Mobility, Shim6.
        let step = match nh {
            0 | 43 | 60 | 135 | 140 => {
                let Some(&hlen) = pkt.get(off + 1) else {
                    return false;
                };
                (usize::from(hlen) + 1) * 8
            }
            // AH (51): payload-len field counts 4-octet units minus 2.
            51 => {
                let Some(&hlen) = pkt.get(off + 1) else {
                    return false;
                };
                (usize::from(hlen) + 2) * 4
            }
            IPV6_FRAGMENT => return pkt.get(off) == Some(&6),
            // Not an extension header: the chain carries no Fragment.
            _ => return false,
        };
        let Some(&next) = pkt.get(off) else {
            return false;
        };
        nh = next;
        off += step;
    }
    false
}

fn read16(pkt: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([pkt[at], pkt[at + 1]])
}

fn write16(pkt: &mut [u8], at: usize, v: u16) {
    pkt[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// Rewrite the TCP ports at `tcp_off` and fix the TCP checksum for them and
/// for the pseudo-header addresses at `addr_range` becoming `new_addrs`.
///
/// A `partial` field holds the uncomplemented pseudo-header sum: only the
/// addresses are adjusted there, without complementing, and the ports are
/// left to the final sum over the segment.
fn rewrite_tcp(
    pkt: &mut [u8],
    tcp_off: usize,
    addr_range: std::ops::Range<usize>,
    new_addrs: &[u8],
    sport: u16,
    dport: u16,
    partial: bool,
) {
    let mut ports = [0u8; 4];
    ports[..2].copy_from_slice(&sport.to_be_bytes());
    ports[2..].copy_from_slice(&dport.to_be_bytes());
    let check_at = tcp_off + 16;
    let check = read16(pkt, check_at);
    let check = if partial {
        !csum_adjust(!check, &pkt[addr_range], new_addrs)
    } else {
        let c = csum_adjust(check, &pkt[addr_range], new_addrs);
        csum_adjust(c, &pkt[tcp_off..tcp_off + 4], &ports)
    };
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
                nat: None,
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
        assert_eq!(nat.translate(&mut syn, false), Verdict::Write);
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
        assert_eq!(nat.translate(&mut reply, false), Verdict::Write);
        assert_eq!(addr4(&reply, 12), "1.1.1.1:443".parse().unwrap());
        assert_eq!(addr4(&reply, 16), "192.168.1.10:51000".parse().unwrap());
        assert_eq!(read16(&reply, 10), ip_check(&reply));
        assert_eq!(read16(&reply, 36), tcp_check(&reply));

        // The client's next segment reuses the entry.
        let mut ack = v4_packet([192, 168, 1, 10], 51000, [1, 1, 1, 1], 443, TCP_ACK);
        assert_eq!(nat.translate(&mut ack, false), Verdict::Write);
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
        assert_eq!(nat.translate(&mut syn, false), Verdict::Write);
        assert_eq!(read16(&syn, 56), tcp_check(&syn));
        let port = read16(&syn, 40);
        let a6: Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let b6: Ipv6Addr = "fdfe:dcba:9876::2".parse().unwrap();
        let mut reply = v6_packet(a6, 40001, b6, port, TCP_SYN | TCP_ACK);
        assert_eq!(nat.translate(&mut reply, false), Verdict::Write);
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
        assert_eq!(nat.translate(&mut ack, false), Verdict::Drop);
        // A reply to a NAT port with no entry.
        let mut reply = v4_packet([172, 31, 0, 1], 40000, [172, 31, 0, 2], 12345, TCP_ACK);
        assert_eq!(nat.translate(&mut reply, false), Verdict::Drop);
        // Into the device's own subnet: would loop.
        let mut lp = v4_packet([192, 168, 1, 10], 2, [172, 31, 0, 3], 80, TCP_SYN);
        assert_eq!(nat.translate(&mut lp, false), Verdict::Drop);
        // UDP goes to lwIP untouched.
        let mut udp = v4_packet([192, 168, 1, 10], 3, [1, 1, 1, 1], 53, 0);
        udp[9] = 17;
        let before = udp.clone();
        assert_eq!(nat.translate(&mut udp, false), Verdict::Stack);
        assert_eq!(udp, before);
        assert_eq!(nat.len(), 0);
    }

    /// The NAT peer addresses (B, b6) are assigned to nothing: a packet
    /// claiming them as source in the client direction is forged and must
    /// not mint an entry. The device addresses (A, a6) are different —
    /// the host's own unsourced sockets take them, so they stay legal
    /// client sources.
    #[test]
    fn nat_peers_are_not_client_sources_but_device_addrs_are() {
        let nat = nat();
        let d: Ipv6Addr = "2606:4700::1111".parse().unwrap();

        let mut forged = v4_packet([172, 31, 0, 2], 51000, [1, 1, 1, 1], 443, TCP_SYN);
        assert_eq!(nat.translate(&mut forged, false), Verdict::Drop);
        let b6: Ipv6Addr = "fdfe:dcba:9876::2".parse().unwrap();
        let mut forged6 = v6_packet(b6, 51000, d, 443, TCP_SYN);
        assert_eq!(nat.translate(&mut forged6, false), Verdict::Drop);
        assert_eq!(nat.len(), 0);

        // The host's own flows source the device address.
        let mut own = v4_packet([172, 31, 0, 1], 51000, [1, 1, 1, 1], 443, TCP_SYN);
        assert_eq!(nat.translate(&mut own, false), Verdict::Write);
        let a6: Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let mut own6 = v6_packet(a6, 51000, d, 443, TCP_SYN);
        assert_eq!(nat.translate(&mut own6, false), Verdict::Write);
    }

    /// `A:port4` alone does not prove a kernel reply — a host dial can
    /// legitimately source the device address on the listener's own port
    /// (a socket bound before the listener was, an ephemeral collision,
    /// or forged like any A-source). Only a packet aimed at the NAT peer
    /// is a reply; anything else from `A:port4` takes the client arm —
    /// dropping it would blackhole a real flow.
    #[test]
    fn reply_arm_only_claims_packets_aimed_at_the_nat_peer() {
        let nat = nat();
        // A host dial whose source port collides with the listener's.
        let mut syn = v4_packet([172, 31, 0, 1], 40000, [1, 1, 1, 1], 443, TCP_SYN);
        assert_eq!(nat.translate(&mut syn, false), Verdict::Write);
        assert_eq!(addr4(&syn, 16), "172.31.0.1:40000".parse().unwrap());
        assert_eq!(nat.len(), 1);
        // And the kernel's replies to that flow un-translate back to it.
        let n = read16(&syn, 20);
        let mut reply = v4_packet([172, 31, 0, 1], 40000, [172, 31, 0, 2], n, TCP_ACK);
        assert_eq!(nat.translate(&mut reply, false), Verdict::Write);
        assert_eq!(addr4(&reply, 12), "1.1.1.1:443".parse().unwrap());
        assert_eq!(addr4(&reply, 16), "172.31.0.1:40000".parse().unwrap());

        // Same on IPv6.
        let a6: Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let b6: Ipv6Addr = "fdfe:dcba:9876::2".parse().unwrap();
        let d: Ipv6Addr = "2606:4700::1111".parse().unwrap();
        let mut syn6 = v6_packet(a6, 40001, d, 443, TCP_SYN);
        assert_eq!(nat.translate(&mut syn6, false), Verdict::Write);
        let n6 = read16(&syn6, 40);
        let mut reply6 = v6_packet(a6, 40001, b6, n6, TCP_ACK);
        assert_eq!(nat.translate(&mut reply6, false), Verdict::Write);
        assert_eq!(read16(&reply6, 40), 443);
        assert_eq!(read16(&reply6, 42), 40001);

        // Aimed at the peer without a NAT entry: still the reply arm,
        // still a drop — stale kernel segments (a swept entry's RST)
        // must not mint a client flow to an on-link address.
        let mut stale = v4_packet([172, 31, 0, 1], 40000, [172, 31, 0, 2], 9, TCP_ACK);
        assert_eq!(nat.translate(&mut stale, false), Verdict::Drop);
        let mut stale6 = v6_packet(a6, 40001, b6, 9, TCP_ACK);
        assert_eq!(nat.translate(&mut stale6, false), Verdict::Drop);
    }

    /// Multicast and broadcast SYNs get no NAT entry; at the half-open
    /// cap the oldest pending entry is evicted to admit a fresh SYN (the
    /// UDP table's `MAX_FLOWS` convention), and an accepted flow still
    /// frees its place.
    #[test]
    fn junk_syns_dropped_and_full_pending_table_evicts_oldest() {
        let nat = nat();
        for dst in [[224, 0, 0, 251], [255, 255, 255, 255]] {
            let mut syn = v4_packet([192, 168, 1, 10], 1, dst, 139, TCP_SYN);
            assert_eq!(nat.translate(&mut syn, false), Verdict::Drop);
        }
        assert_eq!(nat.len(), 0);
        let first_key = (
            SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), 1)),
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 80)),
        );
        for i in 0..PENDING_MAX {
            let port = u16::try_from(i).unwrap() + 1;
            let mut syn = v4_packet([192, 168, 1, 10], port, [1, 1, 1, 1], 80, TCP_SYN);
            assert_eq!(nat.translate(&mut syn, false), Verdict::Write);
        }
        // Over the cap: admitted, not dropped — the oldest (the first
        // SYN's entry) was evicted for it.
        let mut over = v4_packet([192, 168, 1, 11], 1, [1, 1, 1, 1], 80, TCP_SYN);
        assert_eq!(nat.translate(&mut over, false), Verdict::Write);
        {
            let t = nat.table.lock();
            assert_eq!(t.pending, PENDING_MAX);
            assert_eq!(t.by_port.len(), PENDING_MAX);
            assert!(
                !t.by_flow.contains_key(&first_key),
                "the oldest pending entry must be the victim"
            );
            // The evicted entry's deque slot was consumed by the eviction
            // walk; the new SYN pushed its own.
            assert_eq!(t.pending_order.len(), PENDING_MAX);
        }
        // An evicted port's late handshake no longer resolves: the entry
        // is gone, so a stale kernel accept is dropped, never attributed
        // to a flow that reused the port.
        let evicted_port = PORT_FIRST;
        let stale = SocketAddr::V4(SocketAddrV4::new(nat.addrs.b4, evicted_port));
        assert!(nat.accepted(stale).is_none());
        // A surviving pending entry still accepts and frees its place —
        // the second-oldest is now the head of the eviction order.
        let survivor = nat.table.lock().by_flow.values().copied().min().unwrap();
        let peer = SocketAddr::V4(SocketAddrV4::new(nat.addrs.b4, survivor));
        assert!(nat.accepted(peer).is_some());
        assert_eq!(nat.table.lock().pending, PENDING_MAX - 1);
    }

    /// A v6 packet whose next-header chain is `chain` (each entry an
    /// 8-byte header pointing at the following one) terminated by `tail`
    /// — e.g. `(&[43, 44], 6)` is Routing → Fragment → TCP. The tail's
    /// bytes are zeroes; the verdict path never reads past them.
    fn v6_chain_packet(chain: &[u8], tail: u8) -> Vec<u8> {
        let c: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let d: Ipv6Addr = "2606:4700::1111".parse().unwrap();
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&((chain.len() * 8 + 8) as u16).to_be_bytes());
        p.push(chain.first().copied().unwrap_or(tail));
        p.push(64);
        p.extend_from_slice(&c.octets());
        p.extend_from_slice(&d.octets());
        for (i, _) in chain.iter().enumerate() {
            p.push(chain.get(i + 1).copied().unwrap_or(tail));
            // hdr-ext-len 0 (= 8 bytes); for a Fragment header this slot
            // is reserved + the zero offset/M-flag bits — both read as a
            // first fragment, which the verdict does not distinguish.
            p.extend_from_slice(&[0; 7]);
        }
        p.extend_from_slice(&[0; 8]);
        p
    }

    /// The Fragment header may sit anywhere in the extension-header
    /// chain: the old first-header-only check missed `…→Fragment→TCP`
    /// behind Hop-by-Hop/Routing/AH, and lwIP would have reassembled the
    /// TCP flow — reset split-brain against the kernel-owned one.
    #[test]
    fn v6_tcp_fragments_drop_anywhere_in_the_chain() {
        let nat = nat();
        for chain in [
            &[IPV6_FRAGMENT][..],
            &[43, IPV6_FRAGMENT][..],
            &[0, 60, IPV6_FRAGMENT][..],
            &[51, IPV6_FRAGMENT][..],
        ] {
            let mut pkt = v6_chain_packet(chain, 6);
            assert_eq!(
                nat.translate(&mut pkt, false),
                Verdict::Drop,
                "{chain:?} → TCP"
            );
        }
        // A fragment of a non-TCP payload — and extension headers before
        // plain TCP — stay lwIP's, as before.
        for chain in [&[IPV6_FRAGMENT][..], &[43, IPV6_FRAGMENT][..]] {
            let mut pkt = v6_chain_packet(chain, 17);
            assert_eq!(
                nat.translate(&mut pkt, false),
                Verdict::Stack,
                "{chain:?} → UDP"
            );
        }
        for chain in [&[43][..], &[0, 50, 60][..]] {
            let mut pkt = v6_chain_packet(chain, 6);
            assert_eq!(
                nat.translate(&mut pkt, false),
                Verdict::Stack,
                "{chain:?} → TCP, no Fragment"
            );
        }
        // A malformed chain — a header length running past the packet —
        // is lwIP's problem, not a panic.
        let mut bad = v6_chain_packet(&[43, IPV6_FRAGMENT], 6);
        bad[41] = 0xff;
        assert_eq!(nat.translate(&mut bad, false), Verdict::Stack);
        let mut bad = v6_chain_packet(&[51, IPV6_FRAGMENT], 6);
        bad[41] = 0xff;
        assert_eq!(nat.translate(&mut bad, false), Verdict::Stack);
    }

    #[test]
    fn entries_expire_and_closing_flows_get_a_fresh_port() {
        let nat = nat();
        let mut syn = v4_packet([10, 0, 0, 5], 5000, [8, 8, 8, 8], 80, TCP_SYN);
        nat.translate(&mut syn, false);
        let first = read16(&syn, 20);
        let peer = SocketAddr::from((Ipv4Addr::new(172, 31, 0, 2), first));
        assert!(nat.accepted(peer).is_some());
        nat.closed(first);
        // A new SYN on the same 4-tuple while the old one closes.
        let mut syn2 = v4_packet([10, 0, 0, 5], 5000, [8, 8, 8, 8], 80, TCP_SYN);
        nat.translate(&mut syn2, false);
        let second = read16(&syn2, 20);
        assert_ne!(first, second);
        assert_eq!(nat.len(), 2);
        // Age both past their TTLs.
        {
            let mut t = nat.table.lock();
            let Some(old) = Instant::now().checked_sub(PENDING_TTL + Duration::from_secs(1)) else {
                return; // host up for under 31 s
            };
            t.by_port.get_mut(&first).unwrap().state = State::Closing(old);
            t.by_port.get_mut(&second).unwrap().state = State::Pending(old);
        }
        nat.sweep();
        assert_eq!(nat.len(), 0);
        let t = nat.table.lock();
        assert!(t.by_flow.is_empty());
        // The sweep also reclaims the evicted entry's stale deque slot.
        assert!(t.pending_order.is_empty());
    }

    /// A TSO/GRO packet from an offload device: the TCP field holds the
    /// partial pseudo-header sum. After translation, completing the sum the
    /// way the kernel does must give the full checksum of the new packet.
    #[test]
    fn partial_checksum_survives_translation() {
        let nat = nat();
        let mut syn = v4_packet([192, 168, 1, 10], 51000, [1, 1, 1, 1], 443, TCP_SYN);
        // Turn the full checksum into the partial one: the pseudo-header
        // sum, uncomplemented.
        let seg_len = (syn.len() - 20) as u16;
        let mut pseudo = syn[12..20].to_vec();
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&seg_len.to_be_bytes());
        write16(&mut syn, 36, !fold(ones_complement_sum(&pseudo, 0)));
        assert_eq!(nat.translate(&mut syn, true), Verdict::Write);
        crate::tun::vnet::complete_checksum_for_test(&mut syn, 20, 16);
        assert_eq!(read16(&syn, 36), tcp_check(&syn));
        assert_eq!(read16(&syn, 10), ip_check(&syn));
    }

    #[test]
    fn csum_adjust_matches_rfc1624_example() {
        // RFC 1624 §4: HC = 0xDD2F, m = 0x5555 → m' = 0x3285 gives 0x0000.
        assert_eq!(csum_adjust(0xDD2F, &[0x55, 0x55], &[0x32, 0x85]), 0x0000);
    }
}
