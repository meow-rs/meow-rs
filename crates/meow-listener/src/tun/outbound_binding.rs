//! Outbound-interface binding for global route scope (#375, issue #695).
//!
//! `auto-route: global` steers all IPv4 into the TUN, so every socket meow
//! opens must be bound to the physical interface (`SO_BINDTODEVICE`, via
//! `meow_common::set_outbound_interface`) or it loops back into the device.
//! The binding is per-socket and applied at creation: a socket created
//! before it is installed stays unbound for its whole life, and once the
//! split default routes go in its traffic re-enters the TUN — a QUIC or mux
//! session opened by an early startup dial (geodata download, provider
//! fetch, health probe) then loops until it times out.
//!
//! [`OutboundBinding`] is the RAII owner of that process-global binding.
//! The binary installs it *before* the config build performs its first
//! dial and hands it to [`TunListener::with_outbound_binding`]; a listener
//! started without one (config reload) installs its own before touching
//! routes. Either way the listener's device owns it, so it is cleared
//! exactly when the routes it protects go away — listener teardown, reload,
//! or a startup failure.
//!
//! [`TunListener::with_outbound_binding`]: super::TunListener::with_outbound_binding

use std::io;

use tracing::info;

/// Owner of the process-global outbound-interface binding; dropping it
/// clears the binding. At most one should be live at a time — the
/// registry is a single slot, not a stack.
#[must_use = "dropping the binding clears it immediately"]
#[derive(Debug)]
pub struct OutboundBinding(());

impl OutboundBinding {
    /// Install the binding for global route scope. `outbound_interface` is
    /// `tun.outbound-interface`; `None` auto-detects the interface carrying
    /// the IPv4 default route (read before the TUN's own routes exist).
    ///
    /// Fails closed: an error means nothing is installed, and callers must
    /// not install global routes. Non-Linux targets always fail — the
    /// per-socket binding syscall is Linux-only for now (#375).
    pub fn install(outbound_interface: Option<&str>) -> io::Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tun auto-route: global is currently Linux-only (tracked on #375); \
                 use auto-route: fake-ip on this platform",
            ));
        }
        let iface = match outbound_interface {
            Some(name) => name.to_owned(),
            None => super::route::default_interface().map_err(|e| {
                io::Error::other(format!(
                    "tun auto-route: global: could not auto-detect the physical \
                     interface ({e}); set tun.outbound-interface explicitly"
                ))
            })?,
        };
        meow_common::set_outbound_interface(&iface).map_err(|e| {
            io::Error::other(format!(
                "tun auto-route: global: outbound interface binding failed ({e}); \
                 refusing to install default routes without loop avoidance"
            ))
        })?;
        info!(
            "tun: global route scope — outbound sockets bound to '{iface}' \
             (experimental, #375)"
        );
        Ok(Self(()))
    }
}

impl Drop for OutboundBinding {
    fn drop(&mut self) {
        meow_common::clear_outbound_interface();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::OutboundBinding;

    /// One test drives every case because the registry is process-global;
    /// separate `#[test]` fns would race each other.
    #[test]
    fn binding_installs_fails_closed_and_clears_on_drop() {
        assert!(meow_common::outbound_interface().is_none());

        // A missing interface fails closed and installs nothing.
        assert!(OutboundBinding::install(Some("no-such-iface-zz9")).is_err());
        assert!(meow_common::outbound_interface().is_none());

        // Loopback exists on every Linux host.
        let binding = OutboundBinding::install(Some("lo")).expect("lo must exist");
        assert_eq!(meow_common::outbound_interface().as_deref(), Some("lo"));
        drop(binding);
        assert!(meow_common::outbound_interface().is_none());

        // A binding handed to a listener is owned by it: dropping a
        // listener that never ran (startup aborted before the TUN came up)
        // clears the binding instead of leaking it into a TUN-less process.
        let binding = OutboundBinding::install(Some("lo")).expect("lo must exist");
        let listener = super::super::TunListener::new(
            crate::test_rule_tunnel(),
            super::super::TunListenerConfig {
                device: None,
                mtu: 1500,
                inet4_address: "172.19.0.1/30".parse().unwrap(),
                auto_route: true,
                route_scope: super::super::TunRouteScope::Global,
                outbound_interface: Some("lo".into()),
                dns_hijack: false,
                udp_timeout: std::time::Duration::from_secs(60),
                max_connections: 0,
            },
            "meow-tun-test".into(),
        )
        .with_outbound_binding(binding);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some("lo"));
        drop(listener);
        assert!(meow_common::outbound_interface().is_none());
    }
}
