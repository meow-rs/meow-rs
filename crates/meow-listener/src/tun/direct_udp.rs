//! UDP straight off and onto the device for the system stack:
//! the inbound pump parses each datagram's IP/UDP headers and hands the
//! payload to the UDP flow table; the outbound pump builds the reply's
//! headers in one reusable buffer. lwIP is not involved — it saved a
//! netstack task hop, two channel crossings and its own copies per packet
//! each way.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::udp::UdpPkt;
use super::vnet;

/// What [`parse`] made of a plain IP packet.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Parsed {
    Udp(UdpPkt),
    /// UDP the direct path does not carry (fragments, malformed lengths):
    /// dropped.
    Drop,
    /// Not UDP (or IPv6 UDP behind extension headers): lwIP's.
    Other,
}

/// Parse a plain (non-aggregate) IP packet read from the device. The UDP
/// checksum is not verified: the kernel handed the packet over, and the
/// payload is relayed under a new checksum anyway.
pub(super) fn parse(pkt: &[u8]) -> Parsed {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => parse_v4(pkt),
        Some(6) => parse_v6(pkt),
        _ => Parsed::Other,
    }
}

fn parse_v4(pkt: &[u8]) -> Parsed {
    if pkt.len() < 20 || pkt[9] != 17 {
        return Parsed::Other;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if ihl < 20 || total < ihl + 8 || total > pkt.len() {
        return Parsed::Drop;
    }
    if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0 {
        return Parsed::Drop;
    }
    let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
    datagram(&pkt[ihl..total], src, dst)
}

fn parse_v6(pkt: &[u8]) -> Parsed {
    if pkt.len() < 40 || pkt[6] != 17 {
        return Parsed::Other;
    }
    let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    if 40 + payload_len > pkt.len() {
        return Parsed::Drop;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&pkt[8..24]);
    let src = IpAddr::V6(Ipv6Addr::from(a));
    a.copy_from_slice(&pkt[24..40]);
    let dst = IpAddr::V6(Ipv6Addr::from(a));
    datagram(&pkt[40..40 + payload_len], src, dst)
}

fn datagram(udp: &[u8], src: IpAddr, dst: IpAddr) -> Parsed {
    if udp.len() < 8 {
        return Parsed::Drop;
    }
    let len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if len < 8 || len > udp.len() {
        return Parsed::Drop;
    }
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    Parsed::Udp((
        udp[8..len].to_vec(),
        SocketAddr::new(src, sport),
        SocketAddr::new(dst, dport),
    ))
}

/// Whether a packet carries UDP (an aggregate is split before [`parse`]).
pub(super) fn is_udp(pkt: &[u8]) -> bool {
    match pkt.first().map(|b| b >> 4) {
        // A fragment goes to lwIP, which reassembles it.
        Some(4) => {
            pkt.get(9) == Some(&17)
                && pkt
                    .get(6..8)
                    .is_some_and(|f| u16::from_be_bytes([f[0], f[1]]) & 0x3fff == 0)
        }
        // Extension headers (fragments included) go to lwIP too.
        Some(6) => pkt.get(6) == Some(&17),
        _ => false,
    }
}

/// Build into `out` the packet carrying `payload` from `src` to `dst`
/// (both one family), behind a virtio-net header when `vnet`. With the
/// header the UDP checksum is left partial (`NEEDS_CSUM`) for the kernel to
/// finish — or skip, on local delivery; without it IPv4 sends none and
/// IPv6 computes it. Returns `false` for a mixed family or an oversized
/// payload.
pub(super) fn build(
    out: &mut Vec<u8>,
    vnet: bool,
    payload: &[u8],
    src: SocketAddr,
    dst: SocketAddr,
    ip_id: &mut u16,
) -> bool {
    let off = if vnet { vnet::HDR_LEN } else { 0 };
    out.clear();
    out.resize(off, 0);
    let (ip_len, pseudo) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + 8 + payload.len();
            let Ok(total16) = u16::try_from(total) else {
                return false;
            };
            *ip_id = ip_id.wrapping_add(1);
            let mut h = [0u8; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&total16.to_be_bytes());
            h[4..6].copy_from_slice(&ip_id.to_be_bytes());
            h[8] = 64;
            h[9] = 17;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            let c = !fold(sum16(&h, 0));
            h[10..12].copy_from_slice(&c.to_be_bytes());
            out.extend_from_slice(&h);
            let mut p = sum16(&s.octets(), 0);
            p = sum16(&d.octets(), p);
            p += 17 + u64::from(total16 - 20);
            (20, p)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let Ok(plen) = u16::try_from(8 + payload.len()) else {
                return false;
            };
            let mut h = [0u8; 40];
            h[0] = 0x60;
            h[4..6].copy_from_slice(&plen.to_be_bytes());
            h[6] = 17;
            h[7] = 64;
            h[8..24].copy_from_slice(&s.octets());
            h[24..40].copy_from_slice(&d.octets());
            out.extend_from_slice(&h);
            let mut p = sum16(&s.octets(), 0);
            p = sum16(&d.octets(), p);
            p += 17 + u64::from(plen);
            (40, p)
        }
        _ => return false,
    };
    let udp_len = 8 + payload.len();
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded by the u16 checks above"
    )]
    let udp_len16 = udp_len as u16;
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst.port().to_be_bytes());
    out.extend_from_slice(&udp_len16.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let check_at = off + ip_len + 6;
    let check = if vnet {
        vnet::encode_partial_udp(&mut out[..off], ip_len);
        fold(pseudo)
    } else if ip_len == 20 {
        0
    } else {
        match !fold(sum16(&out[off + ip_len..], pseudo)) {
            0 => 0xffff,
            c => c,
        }
    };
    out[check_at..check_at + 2].copy_from_slice(&check.to_be_bytes());
    true
}

fn sum16(data: &[u8], mut sum: u64) -> u64 {
    for w in data.chunks(2) {
        sum += u64::from(u16::from_be_bytes([w[0], w.get(1).copied().unwrap_or(0)]));
    }
    sum
}

fn fold(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation, reason = "folded to 16 bits above")]
    let folded = sum as u16;
    folded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_are_not_direct_udp() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 17;
        assert!(is_udp(&pkt));
        pkt[6] = 0x20; // MF
        assert!(!is_udp(&pkt));
        pkt[6] = 0;
        pkt[7] = 1; // offset
        assert!(!is_udp(&pkt));
    }

    fn udp_check_ok(pkt: &[u8]) -> bool {
        let v4 = pkt[0] >> 4 == 4;
        let (ip_len, mut p) = if v4 {
            (20, sum16(&pkt[12..20], 0))
        } else {
            (40, sum16(&pkt[8..40], 0))
        };
        let udp = &pkt[ip_len..];
        if v4 && udp[6] == 0 && udp[7] == 0 {
            return true;
        }
        p += 17 + udp.len() as u64;
        fold(sum16(udp, p)) == 0xffff
    }

    #[test]
    fn v4_and_v6_round_trip() {
        let mut id = 0;
        for (src, dst) in [
            ("1.1.1.1:53", "192.168.1.10:40000"),
            ("[2606:4700::1111]:443", "[2001:db8::10]:51000"),
        ] {
            let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
            let payload = b"odd-length payload!";
            let mut out = Vec::new();
            assert!(build(&mut out, false, payload, src, dst, &mut id));
            assert!(udp_check_ok(&out), "{src}");
            assert_eq!(parse(&out), Parsed::Udp((payload.to_vec(), src, dst)));
        }
    }

    #[test]
    fn partial_checksum_completes_to_a_valid_one() {
        let mut id = 0;
        let src: SocketAddr = "[2606:4700::1111]:443".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::10]:51000".parse().unwrap();
        let mut out = Vec::new();
        assert!(build(&mut out, true, b"abc", src, dst, &mut id));
        assert!(vnet::needs_csum(&out[..vnet::HDR_LEN]));
        let mut pkt = out[vnet::HDR_LEN..].to_vec();
        vnet::complete_checksum_for_test(&mut pkt, 40, 6);
        assert!(udp_check_ok(&pkt));
    }

    #[test]
    fn fragments_and_bad_lengths_drop_icmp_passes() {
        let mut id = 0;
        let mut out = Vec::new();
        build(
            &mut out,
            false,
            b"x",
            "1.1.1.1:1".parse().unwrap(),
            "2.2.2.2:2".parse().unwrap(),
            &mut id,
        );
        let mut frag = out.clone();
        frag[6] = 0x20; // MF
        assert_eq!(parse(&frag), Parsed::Drop);
        let mut short = out.clone();
        short[24..26].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(parse(&short), Parsed::Drop);
        let mut icmp = out;
        icmp[9] = 1;
        assert_eq!(parse(&icmp), Parsed::Other);
    }
}
