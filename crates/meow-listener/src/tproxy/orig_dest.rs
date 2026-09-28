use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Recover the original destination address from a redirected TCP connection.
///
/// On macOS, queries the pf NAT state table via DIOCNATLOOK.
/// On Linux, uses SO_ORIGINAL_DST getsockopt.
pub fn get_original_dst(stream: &TcpStream, listen_addr: SocketAddr) -> io::Result<SocketAddr> {
    #[cfg(target_os = "macos")]
    {
        macos::get_original_dst(stream, listen_addr)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = listen_addr;
        linux::get_original_dst(stream)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (stream, listen_addr);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent proxy not supported on this platform",
        ))
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpStream;

    // From <net/pfvar.h>
    const DIOCNATLOOK: libc::c_ulong = 0xC0544417;

    // pf address type
    const PF_ADDR_IPV4: u8 = 2; // AF_INET

    // Lookup direction, from <net/pfvar.h>: PF_INOUT = 0, PF_IN = 1, PF_OUT = 2.
    // An `rdr` state's pre-translation destination is keyed under PF_OUT —
    // querying with PF_IN hits the wrong state tree and returns ENOENT for
    // every connection (issue #248). Squid's pf interception and OpenBSD's
    // ftp-proxy both use PF_OUT for this lookup.
    const PF_OUT: u8 = 2;

    /// pf address union — we only handle IPv4 for now.
    #[repr(C)]
    #[derive(Copy, Clone)]
    union PfAddr {
        v4: libc::in_addr,
        v6: libc::in6_addr,
    }

    impl Default for PfAddr {
        fn default() -> Self {
            PfAddr {
                v6: unsafe { mem::zeroed() },
            }
        }
    }

    /// Port/SPI union matching `union pf_state_xport` from <net/pfvar.h>:
    ///
    /// ```c
    /// union pf_state_xport { u_int16_t port; u_int16_t call_id; u_int32_t spi; };
    /// ```
    ///
    /// It is 4 bytes — aligned to the `u32 spi` member. Representing ports as a
    /// bare `u16` (2 bytes) shrinks `pfioc_natlook` to 76 bytes instead of 84,
    /// so the size the kernel reads/writes (encoded in the `DIOCNATLOOK` ioctl
    /// number) no longer matches the buffer we pass — an ABI mismatch that
    /// corrupts the natlook result and reads/writes out of bounds.
    #[repr(C)]
    #[derive(Copy, Clone)]
    union PfStateXport {
        port: u16, // network byte order
        _call_id: u16,
        _spi: u32,
    }

    impl Default for PfStateXport {
        fn default() -> Self {
            PfStateXport { _spi: 0 }
        }
    }

    /// Mirrors `struct pfioc_natlook` from <net/pfvar.h> (84 bytes, verified
    /// against macOS 14 / xnu headers). The exact layout is ABI-sensitive; the
    /// port fields are 4-byte `pf_state_xport` unions, not bare `u16`s.
    ///
    /// Field offsets: saddr@0, daddr@16, rsaddr@32, rdaddr@48, sxport@64,
    /// dxport@68, rsxport@72, rdxport@76, af@80, proto@81, proto_variant@82,
    /// direction@83.
    #[repr(C)]
    #[derive(Default)]
    struct PfiocNatlook {
        saddr: PfAddr,
        daddr: PfAddr,
        rsaddr: PfAddr,
        rdaddr: PfAddr,
        sxport: PfStateXport, // source port (network byte order)
        dxport: PfStateXport, // dest port (network byte order)
        rsxport: PfStateXport,
        rdxport: PfStateXport,
        af: u8,    // address family
        proto: u8, // protocol (IPPROTO_TCP)
        proto_variant: u8,
        direction: u8, // PF_IN or PF_OUT
    }

    // The kernel encodes this size into the DIOCNATLOOK ioctl number, so it
    // must be exactly 84 bytes or the ioctl is rejected / corrupts memory.
    const _: () = assert!(mem::size_of::<PfiocNatlook>() == 84);

    fn natlook_query() -> PfiocNatlook {
        PfiocNatlook {
            af: PF_ADDR_IPV4,
            proto: libc::IPPROTO_TCP as u8,
            direction: PF_OUT,
            ..Default::default()
        }
    }

    pub fn get_original_dst(stream: &TcpStream, listen_addr: SocketAddr) -> io::Result<SocketAddr> {
        let peer = stream.peer_addr().map_err(io::Error::other)?;

        // We only support IPv4 currently
        let (peer_ip, peer_port) = match peer {
            SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
            SocketAddr::V6(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IPv6 transparent proxy not yet supported on macOS",
                ));
            }
        };

        let listen_port = listen_addr.port();

        // /dev/pf is opened once and cached for the process lifetime —
        // opening it per connection cost an open/close syscall pair on
        // every accepted tproxy connection (audit #182). Only success is
        // cached, so a transient failure (pf not loaded yet) can recover.
        static PF_FD: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();
        let pf_fd = match PF_FD.get() {
            Some(f) => f,
            None => {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/pf")?;
                // A racing open just drops the extra fd.
                PF_FD.get_or_init(|| f)
            }
        };

        let mut nl = natlook_query();

        // Source: the connecting client
        nl.saddr.v4 = libc::in_addr {
            s_addr: u32::from(peer_ip).to_be(),
        };
        nl.sxport = PfStateXport {
            port: peer_port.to_be(),
        };

        // Destination: the listen address (after redirection)
        let listen_ip = match listen_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => Ipv4Addr::LOCALHOST,
        };
        nl.daddr.v4 = libc::in_addr {
            s_addr: u32::from(listen_ip).to_be(),
        };
        nl.dxport = PfStateXport {
            port: listen_port.to_be(),
        };

        let ret =
            unsafe { libc::ioctl(pf_fd.as_raw_fd(), DIOCNATLOOK, &mut nl as *mut PfiocNatlook) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // Extract original destination from rdaddr/rdxport
        let orig_ip = unsafe {
            let s_addr = nl.rdaddr.v4.s_addr;
            Ipv4Addr::from(u32::from_be(s_addr))
        };
        // Safety: we only ever write the `port` variant into the xport unions.
        let orig_port = u16::from_be(unsafe { nl.rdxport.port });

        Ok(SocketAddr::new(IpAddr::V4(orig_ip), orig_port))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn struct_sizes_match_kernel() {
            assert_eq!(mem::size_of::<PfStateXport>(), 4);
            assert_eq!(mem::size_of::<PfiocNatlook>(), 84);
        }

        #[test]
        fn redirected_lookup_uses_outbound_state() {
            assert_eq!(natlook_query().direction, PF_OUT);
            assert_eq!(PF_OUT, 2);
        }

        #[test]
        fn field_offsets_match_kernel() {
            // Verified against macOS 14 xnu <net/pfvar.h>.
            assert_eq!(mem::offset_of!(PfiocNatlook, saddr), 0);
            assert_eq!(mem::offset_of!(PfiocNatlook, daddr), 16);
            assert_eq!(mem::offset_of!(PfiocNatlook, rsaddr), 32);
            assert_eq!(mem::offset_of!(PfiocNatlook, rdaddr), 48);
            assert_eq!(mem::offset_of!(PfiocNatlook, sxport), 64);
            assert_eq!(mem::offset_of!(PfiocNatlook, dxport), 68);
            assert_eq!(mem::offset_of!(PfiocNatlook, rsxport), 72);
            assert_eq!(mem::offset_of!(PfiocNatlook, rdxport), 76);
            assert_eq!(mem::offset_of!(PfiocNatlook, af), 80);
            assert_eq!(mem::offset_of!(PfiocNatlook, proto), 81);
            assert_eq!(mem::offset_of!(PfiocNatlook, proto_variant), 82);
            assert_eq!(mem::offset_of!(PfiocNatlook, direction), 83);
        }

        #[test]
        fn ioctl_number_matches_struct_size() {
            // DIOCNATLOOK = _IOWR('D', 23, struct pfioc_natlook).
            // The struct size (84) is encoded in bits 16..29 of the number,
            // so the hardcoded constant must agree with size_of::<PfiocNatlook>.
            let expected: libc::c_ulong = 0xC000_0000
                | ((mem::size_of::<PfiocNatlook>() as libc::c_ulong) << 16)
                | (u64::from(b'D') << 8)
                | 23;
            assert_eq!(DIOCNATLOOK, expected);
            assert_eq!(DIOCNATLOOK, 0xC054_4417);
            // The pre-fix 76-byte struct produced this rejected number.
            assert_ne!(DIOCNATLOOK, 0xC04C_4417);
        }

        #[test]
        fn port_union_round_trip() {
            let xport = PfStateXport {
                port: 443u16.to_be(),
            };
            assert_eq!(u16::from_be(unsafe { xport.port }), 443);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpStream;

    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

    pub fn get_original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
        let fd = stream.as_ref().as_raw_fd();

        // Try IPv4 first
        let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret == 0 {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        }

        // Try IPv6
        let mut addr6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let mut len6: libc::socklen_t = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        let ret6 = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                IP6T_SO_ORIGINAL_DST,
                &mut addr6 as *mut _ as *mut libc::c_void,
                &mut len6,
            )
        };

        if ret6 == 0 {
            let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            let port = u16::from_be(addr6.sin6_port);
            return Ok(SocketAddr::new(IpAddr::V6(ip), port));
        }

        Err(io::Error::last_os_error())
    }
}
