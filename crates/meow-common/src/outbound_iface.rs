//! Outbound-socket interface binding for TUN global-route mode (#375).
//!
//! With `tun.auto-route: global` the split default routes send *all* IPv4
//! traffic into the TUN device — including, without countermeasures, meow's
//! own dials to proxy upstreams and DIRECT destinations, which would re-enter
//! the device and loop. The countermeasure is per-socket: every outbound
//! socket meow creates is bound to the physical interface **before**
//! `connect()`/`bind()`, so its packets take the physical route regardless of
//! the routing table (Linux `SO_BINDTODEVICE`; macOS `IP_BOUND_IF` and
//! Windows `IP_UNICAST_IF` are follow-ups tracked on #375).
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
//! on platforms where the binding syscall is not implemented yet, which lets
//! the TUN listener fail closed instead of starting a looping configuration.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

/// One live owner of the binding.
struct Owner {
    id: u64,
    iface: Arc<str>,
}

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
                tracing::info!("outbound interface binding restored to '{name}' (SO_BINDTODEVICE)");
            }
            None => tracing::info!("outbound interface binding cleared"),
        }
    }
}

/// Install `name` as the physical interface every subsequent outbound
/// socket binds to, superseding (not discarding) any current owner; the
/// binding lasts as long as the returned guard. Validates that the
/// interface exists (Linux `if_nametoindex`). Errors with `Unsupported` on
/// platforms where per-socket binding is not implemented — callers must
/// treat that as fatal for global-route mode, not a warning. On error the
/// registry is left untouched.
pub fn install_outbound_interface(name: &str) -> io::Result<OutboundIfaceGuard> {
    validate_interface(name)?;
    Ok(push_owner(Arc::from(name)))
}

#[cfg(target_os = "linux")]
fn validate_interface(name: &str) -> io::Result<()> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound interface name is empty",
        ));
    }
    let c_name = std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("outbound interface name '{name}' contains a NUL byte"),
        )
    })?;
    // SAFETY: `c_name` is a valid NUL-terminated string for the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("outbound interface '{name}' does not exist"),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_interface(name: &str) -> io::Result<()> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound interface name is empty",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "outbound interface binding ('{name}') is not implemented on this \
             platform yet (tracked on #375; Linux only for now)"
        ),
    ))
}

/// Register a validated interface as the newest owner.
fn push_owner(iface: Arc<str>) -> OutboundIfaceGuard {
    let id = NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed);
    let mut owners = OWNERS.write();
    let superseded = owners.last().map(|o| Arc::clone(&o.iface));
    owners.push(Owner {
        id,
        iface: Arc::clone(&iface),
    });
    drop(owners);
    match superseded {
        Some(prev) if *prev == *iface => {
            tracing::debug!("outbound interface binding '{iface}' taken over by a new owner");
        }
        Some(prev) => tracing::info!(
            "outbound sockets bound to interface '{iface}' (SO_BINDTODEVICE; supersedes '{prev}')"
        ),
        None => tracing::info!("outbound sockets bound to interface '{iface}' (SO_BINDTODEVICE)"),
    }
    OutboundIfaceGuard { id, iface }
}

/// The interface currently in effect (the newest live owner's), if any.
pub fn outbound_interface() -> Option<Arc<str>> {
    OWNERS.read().last().map(|o| Arc::clone(&o.iface))
}

/// Bind `socket` to the installed interface, if one is installed. No-op when
/// none is. Callers must invoke this **before** `connect()`/`bind()` so the
/// very first packet already takes the physical route.
#[cfg(target_os = "linux")]
pub fn apply_outbound_interface(socket: &socket2::Socket) -> io::Result<()> {
    if let Some(name) = outbound_interface() {
        socket.bind_device(Some(name.as_bytes()))?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Id of the owner in effect — distinguishes owners that bind the same
    /// interface (`lo` is the only one every Linux host is guaranteed to
    /// have, and a made-up name would break concurrent socket tests).
    fn current_owner() -> Option<u64> {
        OWNERS.read().last().map(|o| o.id)
    }

    fn live_owners() -> usize {
        OWNERS.read().len()
    }

    fn lo() -> OutboundIfaceGuard {
        install_outbound_interface("lo").expect("lo must exist")
    }

    /// One test drives every case because the registry is process-global;
    /// separate `#[test]` fns would race each other.
    #[test]
    fn owners_install_apply_supersede_and_restore() {
        assert!(outbound_interface().is_none());

        // A bogus interface must be rejected and leave nothing installed.
        assert!(install_outbound_interface("no-such-iface-zz9").is_err());
        assert!(install_outbound_interface("").is_err());
        assert!(install_outbound_interface("lo\0x").is_err());
        assert!(outbound_interface().is_none());

        // Install → apply → drop clears.
        let a = lo();
        assert_eq!(a.interface(), "lo");
        assert_eq!(outbound_interface().as_deref(), Some("lo"));
        assert_eq!(current_owner(), Some(a.id));
        // Binding a fresh socket to lo succeeds and loopback dials still work.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_outbound_interface(&socket).expect("bind_device to lo");
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
        apply_outbound_interface(&socket2).expect("no-op apply");

        // Supersede, then the superseding owner leaves (a rejected reload):
        // the still-live superseded owner is back in effect, not cleared.
        let a = lo();
        let b = lo();
        assert_eq!(current_owner(), Some(b.id));
        drop(b);
        assert_eq!(current_owner(), Some(a.id));
        assert_eq!(outbound_interface().as_deref(), Some("lo"));
        drop(a);
        assert!(outbound_interface().is_none());

        // Out of order (a reload restart: the new binding is installed,
        // then the old listener is torn down): dropping the superseded
        // owner is a no-op — the successor's binding survives.
        let a = lo();
        let b = lo();
        drop(a);
        assert_eq!(current_owner(), Some(b.id));
        assert_eq!(outbound_interface().as_deref(), Some("lo"));
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
        assert_eq!(outbound_interface().as_deref(), Some("lo"));
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
}
