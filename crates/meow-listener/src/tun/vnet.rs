//! virtio-net framing of an offload TUN device (`IFF_VNET_HDR`, opened for
//! `tun.stack: system` on Linux). Each read and write carries a 10-byte
//! header ahead of the IP packet: reads may be TSO/GRO aggregates of up to
//! 64 KiB with a partial (`NEEDS_CSUM`) checksum, which the system stack's
//! NAT translates and writes back whole. lwIP takes plain packets only;
//! [`to_plain`] segments and checksums what goes to it.

pub(super) const HDR_LEN: usize = 10;
/// `VIRTIO_NET_HDR_F_NEEDS_CSUM`: the transport checksum field holds the
/// pseudo-header sum; the rest is summed from `csum_start` on.
const F_NEEDS_CSUM: u8 = 1;

/// Whether a framed read is one packet (no GSO aggregate).
pub(super) fn is_single(hdr: &[u8]) -> bool {
    hdr.get(1) == Some(&0)
}

/// Fill `hdr` for a single UDP packet whose checksum field holds the
/// pseudo-header sum: the kernel finishes it from `ip_len` on. The fields
/// are native-endian (legacy virtio, no `TUNSETVNETLE`).
pub(super) fn encode_partial_udp(hdr: &mut [u8], ip_len: usize) {
    hdr.fill(0);
    hdr[0] = F_NEEDS_CSUM;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "an IP header is 20 or 40 bytes"
    )]
    hdr[6..8].copy_from_slice(&(ip_len as u16).to_ne_bytes());
    hdr[8..10].copy_from_slice(&6u16.to_ne_bytes());
}

/// Whether a framed read's transport checksum is partial.
pub(super) fn needs_csum(hdr: &[u8]) -> bool {
    hdr.first().is_some_and(|f| f & F_NEEDS_CSUM != 0)
}

/// The plain IP packets of one framed read (`framed` = header + packet): a
/// GSO aggregate split into its segments, a partial checksum completed.
/// Malformed framing yields nothing — the packet is dropped.
#[cfg(target_os = "linux")]
pub(super) fn to_plain(framed: &mut [u8]) -> Vec<Vec<u8>> {
    let Ok(hdr) = tun_rs::VirtioNetHdr::decode(&framed[..HDR_LEN]) else {
        return Vec::new();
    };
    let pkt = &mut framed[HDR_LEN..];
    if hdr.gso_type == 0 {
        if hdr.flags & F_NEEDS_CSUM != 0 {
            complete_checksum(pkt, hdr.csum_start, hdr.csum_offset);
        }
        return vec![pkt.to_vec()];
    }
    if hdr.gso_size == 0 {
        return Vec::new();
    }
    let head = usize::from(hdr.hdr_len);
    let count = pkt
        .len()
        .saturating_sub(head)
        .div_ceil(usize::from(hdr.gso_size))
        .max(1);
    let mut out: Vec<Vec<u8>> = (0..count)
        .map(|_| vec![0u8; head + usize::from(hdr.gso_size)])
        .collect();
    let mut sizes = vec![0usize; count];
    let is_v6 = pkt.first().is_some_and(|b| b >> 4 == 6);
    match tun_rs::gso_split(pkt, hdr, &mut out, &mut sizes, 0, is_v6) {
        Ok(n) => {
            out.truncate(n);
            for (seg, &len) in out.iter_mut().zip(&sizes) {
                seg.truncate(len);
            }
            out
        }
        Err(e) => {
            tracing::debug!("tun: dropping a GSO packet lwIP cannot take: {e}");
            Vec::new()
        }
    }
}

/// Without offload framing (off Linux) there is nothing to undo.
#[cfg(not(target_os = "linux"))]
pub(super) fn to_plain(framed: &mut [u8]) -> Vec<Vec<u8>> {
    vec![framed[HDR_LEN..].to_vec()]
}

/// Finish a `NEEDS_CSUM` checksum: sum from `csum_start` on, seeded with the
/// pseudo-header sum the field holds.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn complete_checksum(pkt: &mut [u8], csum_start: u16, csum_offset: u16) {
    let start = usize::from(csum_start);
    let at = start + usize::from(csum_offset);
    if at + 2 > pkt.len() {
        return;
    }
    let mut sum = u64::from(u16::from_be_bytes([pkt[at], pkt[at + 1]]));
    pkt[at] = 0;
    pkt[at + 1] = 0;
    for w in pkt[start..].chunks(2) {
        sum += u64::from(u16::from_be_bytes([w[0], w.get(1).copied().unwrap_or(0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation, reason = "folded to 16 bits above")]
    let mut check = !(sum as u16);
    // UDP sends a computed zero as all ones (zero means "no checksum").
    if check == 0 && csum_offset == 6 {
        check = 0xffff;
    }
    pkt[at..at + 2].copy_from_slice(&check.to_be_bytes());
}

#[cfg(test)]
pub(super) fn complete_checksum_for_test(pkt: &mut [u8], csum_start: u16, csum_offset: u16) {
    complete_checksum(pkt, csum_start, csum_offset);
}
