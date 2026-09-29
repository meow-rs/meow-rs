//! Unicast ARP replies for explicitly selected OpenWrt LAN clients.
use std::net::Ipv4Addr;

fn mac(value: &str) -> anyhow::Result<[u8; 6]> {
    let parts: Vec<_> = value.trim().split(':').collect();
    anyhow::ensure!(parts.len() == 6, "expected a six-byte MAC address");
    let mut bytes = [0; 6];
    for (out, part) in bytes.iter_mut().zip(parts) {
        anyhow::ensure!(part.len() == 2, "invalid MAC address");
        *out = u8::from_str_radix(part, 16)?;
    }
    anyhow::ensure!(bytes != [0; 6] && bytes[0] & 1 == 0, "MAC must be unicast");
    Ok(bytes)
}

fn reply(source: [u8; 6], sender: Ipv4Addr, target: [u8; 6], ip: Ipv4Addr) -> [u8; 42] {
    let mut frame = [0; 42];
    frame[..6].copy_from_slice(&target);
    frame[6..12].copy_from_slice(&source);
    frame[12..22].copy_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 2]);
    frame[22..28].copy_from_slice(&source);
    frame[28..32].copy_from_slice(&sender.octets());
    frame[32..38].copy_from_slice(&target);
    frame[38..42].copy_from_slice(&ip.octets());
    frame
}

/// Send one Ethernet-unicast ARP reply, without relying on arping flavors.
#[cfg(target_os = "linux")]
pub fn send(interface: &str, sender: Ipv4Addr, target: &str, ip: Ipv4Addr) -> anyhow::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    anyhow::ensure!(
        !interface.is_empty()
            && interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
        "invalid interface"
    );
    for addr in [sender, ip] {
        anyhow::ensure!(
            !addr.is_unspecified() && !addr.is_multicast() && !addr.is_broadcast(),
            "invalid IPv4 address"
        );
    }
    let target = mac(target)?;
    let source = mac(&std::fs::read_to_string(format!(
        "/sys/class/net/{interface}/address"
    ))?)?;
    let name = std::ffi::CString::new(interface)?;
    // SAFETY: CString is NUL-terminated and remains alive for this call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    anyhow::ensure!(index != 0, "interface not found");
    let protocol = (libc::ETH_P_ARP as u16).to_be();
    // SAFETY: no pointers; the returned descriptor is checked and owned below.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(protocol),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd is a newly created valid descriptor with one owner.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: all-zero initialization is valid for sockaddr_ll.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = protocol;
    address.sll_ifindex = index as i32;
    address.sll_halen = 6;
    address.sll_addr[..6].copy_from_slice(&target);
    let frame = reply(source, sender, target, ip);
    // SAFETY: both pointers refer to initialized buffers with the supplied lengths.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    anyhow::ensure!(sent as usize == frame.len(), "short ARP send");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reply_addresses_only_the_selected_client() {
        let source = mac("02:00:00:00:00:01").unwrap();
        let target = mac("02:00:00:00:00:02").unwrap();
        let frame = reply(
            source,
            Ipv4Addr::new(192, 168, 1, 1),
            target,
            Ipv4Addr::new(192, 168, 1, 20),
        );
        assert_eq!(&frame[..6], &target);
        assert_eq!(&frame[32..38], &target);
        assert_eq!(&frame[20..22], &[0, 2]);
        assert_eq!(&frame[28..32], &[192, 168, 1, 1]);
        assert_eq!(&frame[38..42], &[192, 168, 1, 20]);
        assert!(mac("ff:ff:ff:ff:ff:ff").is_err());
        assert!(mac("01:00:5e:00:00:01").is_err());
    }
}
