use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::lwip::*;

// FIXME Need to verify the byte order of Ipv6 address in lwIP.

pub fn to_socket_addr(addr: &ip_addr_t, port: u16_t) -> SocketAddr {
    unsafe {
        match addr.type_ {
            // Ipv4
            0 => SocketAddr::new(IpAddr::V4(addr.u_addr.ip4.addr.to_ne_bytes().into()), port),
            // Ipv6
            6 => {
                let addr = addr.u_addr.ip6.addr;
                let p0 = addr[0].to_ne_bytes();
                let p1 = addr[1].to_ne_bytes();
                let p2 = addr[2].to_ne_bytes();
                let p3 = addr[3].to_ne_bytes();
                let mut p = [0u8; 16];
                p[0..4].copy_from_slice(&p0);
                p[4..8].copy_from_slice(&p1);
                p[8..12].copy_from_slice(&p2);
                p[12..16].copy_from_slice(&p3);
                let addr = Ipv6Addr::from(p);
                SocketAddr::new(IpAddr::V6(addr), port)
            }
            // IPADDR_TYPE_ANY: the dual-stack wildcard the stack's own UDP
            // pcb is bound to (`ip_addr_any_type`). Not an error — it used
            // to log the warning below on every TUN start.
            46 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            _ => {
                log::warn!("Unsupported IP address type");
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        }
    }
}

pub fn to_ip_addr_t(ip: IpAddr) -> ip_addr_t {
    match ip {
        IpAddr::V4(ip4) => {
            ip_addr_t {
                u_addr: ip_addr__bindgen_ty_1 {
                    ip4: ip4_addr {
                        addr: u32::from_ne_bytes(ip4.octets()),
                    },
                },
                type_: 0, // Ipv4
            }
        }
        IpAddr::V6(ip6) => {
            let bytes = ip6.octets();
            let mut p0 = [0u8; 4];
            let mut p1 = [0u8; 4];
            let mut p2 = [0u8; 4];
            let mut p3 = [0u8; 4];
            p0.copy_from_slice(&bytes[0..4]);
            p1.copy_from_slice(&bytes[4..8]);
            p2.copy_from_slice(&bytes[8..12]);
            p3.copy_from_slice(&bytes[12..16]);
            let addr = [
                u32::from_ne_bytes(p0),
                u32::from_ne_bytes(p1),
                u32::from_ne_bytes(p2),
                u32::from_ne_bytes(p3),
            ];
            ip_addr_t {
                u_addr: ip_addr__bindgen_ty_1 {
                    ip6: ip6_addr { addr, zone: 0 },
                },
                type_: 6, // Ipv6
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_to_socket_addr() {
        unsafe {
            let addr = to_socket_addr(&ip_addr_any_type, 80);
            assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80));
            let mut v6_addr = ip_addr_any_type;
            v6_addr.type_ = 6;
            let addr = to_socket_addr(&v6_addr, 80);
            assert_eq!(addr, SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80));
        }
    }

    #[test]
    fn test_to_ip_addr_t() {
        let addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(to_ip_addr_t(addr).type_, 0);
        let addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        assert_eq!(to_ip_addr_t(addr).type_, 6);
    }
}
