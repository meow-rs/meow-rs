//! Outbound-socket interface binding for TUN global-route mode (#375).
//!
//! With `tun.auto-route: global` the split default routes send *all*
//! traffic into the TUN device — including, without countermeasures, meow's
//! own dials to proxy upstreams and DIRECT destinations, which would re-enter
//! the device and loop. The countermeasure is per-socket: every outbound
//! socket meow creates is bound to the physical interface **before**
//! `connect()`/`bind()`, so its packets take the physical route regardless of
//! the routing table. The binding is per platform:
//!
//! | Platform | Socket option | Keyed by |
//! |----------|---------------|----------|
//! | Linux | `SO_BINDTODEVICE` | interface name |
//! | macOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` | interface index |
//! | Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` | interface index |
//!
//! The index-keyed platforms resolve the index once, at install time. An
//! interface that is destroyed and re-created under the same name gets a
//! new index, which the binding does not follow until it is re-installed
//! (a TUN listener restart).
//!
//! On macOS a socket scoped to a physical interface cannot reach an IPv4
//! loopback peer (`connect()` fails with `EADDRNOTAVAIL`), and loopback
//! traffic never follows the TUN's routes anyway — so on the index-keyed
//! platforms TCP dials to a loopback address, and UDP sockets pinned to a
//! loopback local address, are left unbound (`binds_peer`). Linux keeps
//! binding every socket, as it did before those platforms were added.
//!
//! This module is the process-global registry for that interface, mirroring
//! the `SocketProtector` pattern in [`crate::socket_protect`]: the owners of
//! global route scope install the interface with
//! [`install_outbound_interface`], and the dial chokepoints
//! ([`crate::connect_tcp`], [`crate::bind_udp`], plus the marked-socket path
//! in `meow-proxy`) apply it to each socket.
//!
//! # Owners
//!
//! The binding is owned, not set: [`install_outbound_interface`] returns an
//! [`OutboundIfaceGuard`], and dropping the guard gives the binding up.
//! Owners can overlap — a config reload installs the *new* configuration's
//! binding before its first dial, while the old TUN listener (and its own
//! binding) is still running (issue #695) — so the registry keeps every
//! live owner in installation order and the **most recently installed live
//! owner** decides the interface:
//!
//! - installing supersedes the current owner without invalidating it;
//! - dropping the current owner hands the binding back to the newest owner
//!   still alive (or clears it when none is left), so a rejected reload
//!   restores the running listener's binding;
//! - dropping a superseded owner changes nothing, so an old listener torn
//!   down after its successor installed cannot clear or clobber the
//!   successor's binding.
//!
//! The registry itself compiles on every platform so call sites stay free of
//! `cfg` spaghetti; [`install_outbound_interface`] fails with `Unsupported`
//! on platforms where the binding syscall is not implemented, which lets
//! the TUN listener fail closed instead of starting a looping configuration.

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

/// One live owner of the binding.
struct Owner {
    id: u64,
    iface: Arc<str>,
    /// OS interface index, resolved when the owner installed. What the
    /// index-keyed platforms bind to; Linux binds by name.
    index: u32,
}

/// The socket option the binding uses on this platform, for log lines.
const MECHANISM: &str = if cfg!(target_os = "macos") {
    "IP_BOUND_IF"
} else if cfg!(target_os = "windows") {
    "IP_UNICAST_IF"
} else {
    "SO_BINDTODEVICE"
};

/// Live owners in installation order; the last one is in effect. Holds at
/// most a handful of entries — one per overlapping owner (running listener,
/// in-flight reload).
static OWNERS: RwLock<Vec<Owner>> = RwLock::new(Vec::new());

/// Owner identity source. Interface names cannot identify owners: two
/// overlapping owners routinely bind the same interface.
static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);

/// Ownership of one installation of the outbound-interface binding,
/// returned by [`install_outbound_interface`]. Dropping it gives the
/// binding up: the newest owner still alive takes over, or the binding is
/// cleared when none is left (see the [module docs](self)).
#[must_use = "dropping the guard gives the binding up immediately"]
#[derive(Debug)]
pub struct OutboundIfaceGuard {
    id: u64,
    iface: Arc<str>,
}

impl OutboundIfaceGuard {
    /// The interface this owner installed. Not necessarily the one in
    /// effect — a newer owner may have superseded it
    /// (see [`outbound_interface`]).
    pub fn interface(&self) -> &str {
        &self.iface
    }
}

impl Drop for OutboundIfaceGuard {
    fn drop(&mut self) {
        let mut owners = OWNERS.write();
        let Some(pos) = owners.iter().position(|o| o.id == self.id) else {
            return;
        };
        owners.remove(pos);
        if pos != owners.len() {
            // A superseded owner left; the binding in effect is unchanged.
            return;
        }
        let restored = owners.last().map(|o| Arc::clone(&o.iface));
        drop(owners);
        match restored {
            Some(name) if *name == *self.iface => {}
            Some(name) => {
                tracing::info!("outbound interface binding restored to '{name}' ({MECHANISM})");
            }
            None => tracing::info!("outbound interface binding cleared"),
        }
    }
}

/// Install `name` as the physical interface every subsequent outbound
/// socket binds to, superseding (not discarding) any current owner; the
/// binding lasts as long as the returned guard. Validates that the
/// interface exists by resolving its index (`if_nametoindex` on Linux and
/// macOS; on Windows `name` is the interface *alias*, e.g. `Ethernet` or
/// `Wi-Fi`). Errors with `Unsupported` on platforms where per-socket
/// binding is not implemented — callers must treat that as fatal for
/// global-route mode, not a warning. On error the registry is left
/// untouched.
pub fn install_outbound_interface(name: &str) -> io::Result<OutboundIfaceGuard> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound interface name is empty",
        ));
    }
    if name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("outbound interface name '{name}' contains a NUL byte"),
        ));
    }
    let index = interface_index(name)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("outbound interface '{name}' does not exist"),
        )
    })?;
    Ok(push_owner(Arc::from(name), index))
}

/// Resolve a NUL-free interface name to its index; `None` = no such
/// interface.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn interface_index(name: &str) -> io::Result<Option<u32>> {
    let c_name =
        std::ffi::CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c_name` is a valid NUL-terminated string for the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    Ok((index != 0).then_some(index))
}

/// Resolve an interface alias (`Ethernet`, `Wi-Fi`, …) to its index;
/// `None` = no such interface.
#[cfg(target_os = "windows")]
#[allow(
    clippy::unnecessary_wraps,
    reason = "signature shared with the other platforms' interface_index"
)]
fn interface_index(name: &str) -> io::Result<Option<u32>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let alias: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `NET_LUID_LH` is a plain 64-bit union; all-zero is valid.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    // SAFETY: `alias` is NUL-terminated UTF-16 and `luid` a valid out-pointer.
    if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &raw mut luid) } != 0 {
        return Ok(None);
    }
    let mut index = 0u32;
    // SAFETY: both pointers reference live locals for the call.
    if unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut index) } != 0 {
        return Ok(None);
    }
    Ok((index != 0).then_some(index))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn interface_index(name: &str) -> io::Result<Option<u32>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "outbound interface binding ('{name}') is not implemented on this \
             platform (Linux, macOS and Windows only; #375)"
        ),
    ))
}

/// The IPv4 metric of interface `index`. Windows ranks competing default
/// routes by route metric **plus** this, so default-interface detection
/// needs both.
#[cfg(target_os = "windows")]
pub fn interface_metric_v4(index: u32) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // SAFETY: the row is plain data; `InitializeIpInterfaceEntry` then sets
    // every field to its documented default.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: `row` is a valid, exclusively borrowed row for both calls.
    unsafe {
        InitializeIpInterfaceEntry(&raw mut row);
        row.Family = AF_INET;
        row.InterfaceIndex = index;
        (GetIpInterfaceEntry(&raw mut row) == 0).then_some(row.Metric)
    }
}

/// Register a validated interface as the newest owner.
fn push_owner(iface: Arc<str>, index: u32) -> OutboundIfaceGuard {
    let id = NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed);
    let mut owners = OWNERS.write();
    let superseded = owners.last().map(|o| Arc::clone(&o.iface));
    owners.push(Owner {
        id,
        iface: Arc::clone(&iface),
        index,
    });
    drop(owners);
    match superseded {
        Some(prev) if *prev == *iface => {
            tracing::debug!("outbound interface binding '{iface}' taken over by a new owner");
        }
        Some(prev) => tracing::info!(
            "outbound sockets bound to interface '{iface}' ({MECHANISM}; supersedes '{prev}')"
        ),
        None => tracing::info!("outbound sockets bound to interface '{iface}' ({MECHANISM})"),
    }
    OutboundIfaceGuard { id, iface }
}

/// The interface currently in effect (the newest live owner's), if any.
pub fn outbound_interface() -> Option<Arc<str>> {
    OWNERS.read().last().map(|o| Arc::clone(&o.iface))
}

/// Whether a socket talking to `peer` — a TCP dial's destination, or the
/// local address a UDP socket is pinned to — takes the binding.
///
/// Loopback is exempt on the index-keyed platforms (see the
/// [module docs](self)): the traffic never follows the TUN's routes, and
/// macOS refuses an IPv4 loopback connect from an interface-scoped socket.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn binds_peer(peer: IpAddr) -> bool {
    cfg!(target_os = "linux") || !is_loopback(peer)
}

/// Loopback including the IPv4-mapped form a dual-stack socket dials.
#[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Bind `socket` — created in `domain` — to the installed interface, if one
/// is installed. No-op when none is. Callers must invoke this **before**
/// `connect()`/`bind()` so the very first packet already takes the physical
/// route.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn apply_outbound_interface(
    socket: &socket2::Socket,
    domain: socket2::Domain,
) -> io::Result<()> {
    let Some((name, index)) = OWNERS
        .read()
        .last()
        .map(|o| (Arc::clone(&o.iface), o.index))
    else {
        return Ok(());
    };
    bind_socket(socket, domain, &name, index)
}

/// Linux: `SO_BINDTODEVICE`, by name — one option covers both families.
#[cfg(target_os = "linux")]
fn bind_socket(
    socket: &socket2::Socket,
    _domain: socket2::Domain,
    name: &str,
    _index: u32,
) -> io::Result<()> {
    socket.bind_device(Some(name.as_bytes()))
}

/// macOS: `IP_BOUND_IF` on an IPv4 socket, `IPV6_BOUND_IF` on an IPv6 one.
/// The IPv6 option scopes the whole socket, so a dual-stack socket's
/// IPv4-mapped traffic is covered too.
#[cfg(target_os = "macos")]
fn bind_socket(
    socket: &socket2::Socket,
    domain: socket2::Domain,
    _name: &str,
    index: u32,
) -> io::Result<()> {
    let index = std::num::NonZeroU32::new(index);
    if domain == socket2::Domain::IPV6 {
        socket.bind_device_by_index_v6(index)
    } else {
        socket.bind_device_by_index_v4(index)
    }
}

/// Windows: `IP_UNICAST_IF` on an IPv4 socket, `IPV6_UNICAST_IF` on an IPv6
/// one. A dual-stack IPv6 socket sends its IPv4-mapped traffic by the IPv4
/// option, so an IPv6 socket gets that one as well — best effort, because
/// a v6-only socket refuses it.
#[cfg(target_os = "windows")]
fn bind_socket(
    socket: &socket2::Socket,
    domain: socket2::Domain,
    _name: &str,
    index: u32,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET, SOCKET_ERROR,
    };

    let raw = socket.as_raw_socket() as SOCKET;
    let set = |level: i32, option: i32, value: u32| -> io::Result<()> {
        // SAFETY: `raw` is a live socket for the duration of the borrow and
        // `value` a 4-byte option value, as both options expect.
        let ret = unsafe { setsockopt(raw, level, option, (&raw const value).cast(), 4) };
        if ret == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    if domain == socket2::Domain::IPV6 {
        set(IPPROTO_IPV6, IPV6_UNICAST_IF, index)?;
        let _ = set(IPPROTO_IP, IP_UNICAST_IF, unicast_if_v4(index));
        Ok(())
    } else {
        set(IPPROTO_IP, IP_UNICAST_IF, unicast_if_v4(index))
    }
}

/// The `IP_UNICAST_IF` option value for interface `index`: the IPv4 option
/// takes the index in **network** byte order, while `IPV6_UNICAST_IF` takes
/// it in host byte order.
#[cfg(any(test, target_os = "windows"))]
const fn unicast_if_v4(index: u32) -> u32 {
    index.to_be()
}

#[cfg(test)]
mod pure_tests {
    use super::*;

    #[test]
    fn ip_unicast_if_value_is_the_index_in_network_byte_order() {
        assert_eq!(unicast_if_v4(5).to_ne_bytes(), [0, 0, 0, 5]);
        assert_eq!(unicast_if_v4(0x0102_0304).to_ne_bytes(), [1, 2, 3, 4]);
    }

    #[test]
    fn loopback_peers_include_the_mapped_form() {
        for ip in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"] {
            assert!(is_loopback(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "192.0.2.1",
            "0.0.0.0",
            "::",
            "2001:db8::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(!is_loopback(ip.parse().unwrap()), "{ip}");
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    /// The loopback interface: the only one every host is guaranteed to
    /// have, and binding to it keeps the concurrent loopback socket tests
    /// in this binary working (a made-up name would break them).
    const LO: &str = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };

    /// Id of the owner in effect — distinguishes owners that bind the same
    /// interface.
    fn current_owner() -> Option<u64> {
        OWNERS.read().last().map(|o| o.id)
    }

    fn live_owners() -> usize {
        OWNERS.read().len()
    }

    fn lo() -> OutboundIfaceGuard {
        install_outbound_interface(LO).expect("loopback must exist")
    }

    /// One test drives every case because the registry is process-global;
    /// separate `#[test]` fns would race each other.
    #[test]
    fn owners_install_apply_supersede_and_restore() {
        assert!(outbound_interface().is_none());

        // A bogus interface must be rejected and leave nothing installed.
        assert!(install_outbound_interface("no-such-iface-zz9").is_err());
        assert!(install_outbound_interface("").is_err());
        assert!(install_outbound_interface("lo0\0x").is_err());
        assert!(outbound_interface().is_none());

        // Install → apply → drop clears.
        let a = lo();
        assert_eq!(a.interface(), LO);
        assert_eq!(outbound_interface().as_deref(), Some(LO));
        assert_eq!(current_owner(), Some(a.id));
        // Binding a fresh socket to loopback succeeds, in both families
        // and for both socket types.
        for domain in [socket2::Domain::IPV4, socket2::Domain::IPV6] {
            for (ty, proto) in [
                (socket2::Type::STREAM, socket2::Protocol::TCP),
                (socket2::Type::DGRAM, socket2::Protocol::UDP),
            ] {
                let socket = socket2::Socket::new(domain, ty, Some(proto)).unwrap();
                apply_outbound_interface(&socket, domain).expect("bind to loopback");
                assert_bound_to_loopback(&socket, domain);
            }
        }
        dial_chokepoints_bind_their_sockets();
        drop(a);
        assert!(outbound_interface().is_none());
        assert_eq!(live_owners(), 0);

        // With nothing installed, apply is a no-op.
        let socket2 = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_outbound_interface(&socket2, socket2::Domain::IPV4).expect("no-op apply");
        #[cfg(target_os = "macos")]
        assert_eq!(socket2.device_index_v4().unwrap(), None);

        // Supersede, then the superseding owner leaves (a rejected reload):
        // the still-live superseded owner is back in effect, not cleared.
        let a = lo();
        let b = lo();
        assert_eq!(current_owner(), Some(b.id));
        drop(b);
        assert_eq!(current_owner(), Some(a.id));
        assert_eq!(outbound_interface().as_deref(), Some(LO));
        drop(a);
        assert!(outbound_interface().is_none());

        // Out of order (a reload restart: the new binding is installed,
        // then the old listener is torn down): dropping the superseded
        // owner is a no-op — the successor's binding survives.
        let a = lo();
        let b = lo();
        drop(a);
        assert_eq!(current_owner(), Some(b.id));
        assert_eq!(outbound_interface().as_deref(), Some(LO));
        // The superseding owner outlived its predecessor: nothing to
        // restore, so its drop clears.
        drop(b);
        assert!(outbound_interface().is_none());
        assert_eq!(live_owners(), 0);

        // Three deep, middle owner dropped first: the top stays in effect,
        // and the top leaving skips the dead middle and restores the bottom.
        let a = lo();
        let b = lo();
        let c = lo();
        drop(b);
        assert_eq!(current_owner(), Some(c.id));
        drop(c);
        assert_eq!(current_owner(), Some(a.id));
        assert_eq!(outbound_interface().as_deref(), Some(LO));
        drop(a);
        assert!(outbound_interface().is_none());

        // Three deep, unwound strictly in order.
        let a = lo();
        let b = lo();
        let c = lo();
        drop(c);
        assert_eq!(current_owner(), Some(b.id));
        drop(b);
        assert_eq!(current_owner(), Some(a.id));
        drop(a);
        assert!(outbound_interface().is_none());

        // Three deep, bottom first then top: the middle takes over.
        let a = lo();
        let b = lo();
        let c = lo();
        drop(a);
        assert_eq!(current_owner(), Some(c.id));
        drop(c);
        assert_eq!(current_owner(), Some(b.id));
        drop(b);
        assert!(outbound_interface().is_none());
        assert_eq!(live_owners(), 0);

        // A failed install while an owner is live leaves it in effect.
        let a = lo();
        assert!(install_outbound_interface("no-such-iface-zz9").is_err());
        assert_eq!(current_owner(), Some(a.id));
        assert_eq!(live_owners(), 1);
        drop(a);
        assert!(outbound_interface().is_none());
    }

    /// The dial chokepoints behind `connect_tcp` / `bind_udp`, driven with
    /// the loopback interface installed. Called from the one registry test
    /// (the chokepoints read the process-global registry), and through the
    /// `*_iface_bound` halves directly: the public entry points prefer a
    /// `SocketProtector`, which concurrent tests in this binary install.
    fn dial_chokepoints_bind_their_sockets() {
        use crate::socket_protect::{bind_udp_iface_bound, connect_tcp_iface_bound};
        use socket2::{Domain, SockRef};
        use std::net::SocketAddr;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // TCP: the dial is bound and still reaches a loopback listener.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let stream = connect_tcp_iface_bound(addr).await.expect("loopback dial");
            listener.accept().await.unwrap();
            assert_bound_to_loopback(&SockRef::from(&stream), Domain::IPV4);

            // UDP: a wildcard socket is bound and carries a datagram.
            let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let wildcard: SocketAddr = "0.0.0.0:0".parse().unwrap();
            let socket = bind_udp_iface_bound(wildcard).expect("wildcard bind");
            assert_bound_to_loopback(&SockRef::from(&socket), Domain::IPV4);
            socket
                .send_to(b"ping", receiver.local_addr().unwrap())
                .await
                .unwrap();
            let mut buf = [0u8; 8];
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");

            let wildcard6: SocketAddr = "[::]:0".parse().unwrap();
            let socket6 = bind_udp_iface_bound(wildcard6).expect("v6 wildcard bind");
            assert_bound_to_loopback(&SockRef::from(&socket6), Domain::IPV6);

            // The scope is enforced by the kernel, not just recorded: a
            // socket bound to loopback has no route to a non-loopback
            // destination (TEST-NET-1 — nothing leaves the host either way).
            #[cfg(target_os = "macos")]
            {
                let outside: SocketAddr = "192.0.2.1:9".parse().unwrap();
                let err = connect_tcp_iface_bound(outside)
                    .await
                    .expect_err("loopback-scoped socket must not reach TEST-NET-1");
                assert_eq!(err.raw_os_error(), Some(libc::ENETUNREACH), "{err}");
                let err = socket.send_to(b"x", outside).await.expect_err("scoped UDP");
                assert_eq!(err.raw_os_error(), Some(libc::ENETUNREACH), "{err}");

                // A UDP socket pinned to a loopback address is exempt.
                let pinned: SocketAddr = "127.0.0.1:0".parse().unwrap();
                let socket = bind_udp_iface_bound(pinned).expect("loopback bind");
                assert_eq!(SockRef::from(&socket).device_index_v4().unwrap(), None);
                assert!(!binds_peer(pinned.ip()) && binds_peer(outside.ip()));
            }
        });
    }

    /// The kernel reports the binding the socket option installed.
    fn assert_bound_to_loopback(socket: &socket2::Socket, domain: socket2::Domain) {
        #[cfg(target_os = "macos")]
        {
            let want = interface_index(LO).unwrap();
            let got = if domain == socket2::Domain::IPV6 {
                socket.device_index_v6().unwrap()
            } else {
                socket.device_index_v4().unwrap()
            };
            assert_eq!(got.map(std::num::NonZeroU32::get), want);
        }
        #[cfg(target_os = "linux")]
        {
            let _ = domain;
            assert_eq!(socket.device().unwrap().as_deref(), Some(LO.as_bytes()));
        }
    }
}
