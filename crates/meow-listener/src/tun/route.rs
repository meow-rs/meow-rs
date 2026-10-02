//! RAII route installation for the TUN inbound's `auto-route`.
//!
//! v1 deliberately routes only the fake-IP range into the device (see the
//! module docs in `mod.rs` for the loop-freedom argument). Routes are added
//! with the blocking `route_manager` API at listener startup and removed on
//! drop; a failed add is a warning, not a fatal error, because the device
//! subnet's own on-link route frequently already covers the range (in which
//! case some platforms report "route exists").

use ipnet::IpNet;
use route_manager::{Route, RouteManager};
use tracing::{debug, warn};

pub(super) struct RouteGuard {
    manager: RouteManager,
    installed: Vec<Route>,
}

impl RouteGuard {
    /// Install one on-link route per net through interface `if_index`.
    /// Individual failures are logged and skipped so a pre-existing
    /// equivalent route does not abort listener startup.
    pub(super) fn setup(if_index: u32, nets: &[IpNet]) -> std::io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let mut installed = Vec::with_capacity(nets.len());
        for net in nets {
            let route = Route::new(net.network(), net.prefix_len()).with_if_index(if_index);
            match manager.add(&route) {
                Ok(()) => {
                    debug!("tun auto-route: added {net} via if_index {if_index}");
                    installed.push(route);
                }
                Err(e) => warn!(
                    "tun auto-route: failed to add {net} via if_index {if_index}: {e} \
                     (continuing — the device subnet may already cover it)"
                ),
            }
        }
        Ok(Self { manager, installed })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for route in &self.installed {
            if let Err(e) = self.manager.delete(route) {
                warn!("tun auto-route: failed to remove {route}: {e}");
            }
        }
    }
}

/// Detect the physical interface carrying the IPv4 default route, for
/// global route scope's outbound-socket binding (#375).
///
/// - Linux reads `/proc/net/route` and returns the interface of the first
///   UP `0.0.0.0/0` entry.
/// - macOS and Windows list the routing table (`route_manager`) and return
///   the interface of the best `0.0.0.0/0` route — see
///   [`pick_default_interface`]. On Windows the name is the interface
///   alias (`Ethernet`, `Wi-Fi`, …).
///
/// The TUN's own split defaults are never the answer, even when they are
/// installed: a config reload detects the new configuration's interface
/// while the old global-scope listener's routes still exist (issue #695),
/// and the kernel lists `0.0.0.0/1` *before* the real default — so the
/// mask must be `/0`, not just the destination.
pub(super) fn default_interface() -> std::io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route")?;
        parse_default_interface(&table).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no IPv4 default route found in /proc/net/route",
            )
        })
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let routes = RouteManager::new()?.list()?;
        pick_default_interface(routes.iter().map(default_candidate)).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no IPv4 default route found in the routing table",
            )
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "default-interface auto-detection is not implemented on this platform \
             (Linux, macOS and Windows only; #375)",
        ))
    }
}

/// The fields of a routing-table entry that decide default-interface
/// detection on macOS and Windows, lifted out of `route_manager::Route`
/// (whose platform-specific accessors only exist on their own target) so
/// the selection is unit-testable on every host.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
#[derive(Debug, Clone)]
struct DefaultCandidate {
    destination: std::net::IpAddr,
    prefix: u8,
    if_name: Option<String>,
    /// macOS `RTF_IFSCOPE`: a default that only applies to sockets already
    /// scoped to its interface — every non-primary interface has one.
    scoped: bool,
    /// Effective metric, lower wins. Windows: route metric + interface
    /// metric. macOS has no metric; the table order decides.
    metric: u32,
}

#[cfg(target_os = "macos")]
fn default_candidate(route: &Route) -> DefaultCandidate {
    DefaultCandidate {
        destination: route.destination(),
        prefix: route.prefix(),
        if_name: route.if_name().cloned(),
        scoped: route.if_scope(),
        metric: 0,
    }
}

#[cfg(target_os = "windows")]
fn default_candidate(route: &Route) -> DefaultCandidate {
    let interface_metric = route
        .if_index()
        .and_then(meow_common::outbound_iface::interface_metric_v4)
        .unwrap_or(0);
    DefaultCandidate {
        destination: route.destination(),
        prefix: route.prefix(),
        if_name: route.if_name().cloned(),
        scoped: false,
        metric: route.metric().unwrap_or(0).saturating_add(interface_metric),
    }
}

/// Pure selection behind [`default_interface`] on macOS and Windows: the
/// interface of the unscoped IPv4 `0.0.0.0/0` route with the lowest
/// metric, the first listed winning a tie. Requiring prefix `/0` skips the
/// TUN's own `0.0.0.0/1` split route, which shares the destination.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn pick_default_interface(routes: impl IntoIterator<Item = DefaultCandidate>) -> Option<String> {
    routes
        .into_iter()
        .filter(|r| {
            r.prefix == 0
                && r.destination == std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                && !r.scoped
        })
        .filter_map(|r| r.if_name.map(|name| (r.metric, name)))
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, name)| name)
}

/// Pure parser behind [`default_interface`], split out for unit testing on
/// every host (hence `test` in the cfg — only Linux uses it at runtime).
/// `/proc/net/route` columns: Iface, Destination (hex LE),
/// Gateway, Flags (hex; bit 0 = RTF_UP), RefCnt, Use, Metric, Mask, … A
/// default route has destination `00000000`, mask `00000000` (a split
/// `0.0.0.0/1` shares the destination but has mask `00000080`) and the UP
/// flag set.
#[cfg(any(target_os = "linux", test))]
fn parse_default_interface(table: &str) -> Option<String> {
    for line in table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let [iface, dest, _gateway, flags, _refcnt, _use, _metric, mask, ..] = cols[..] else {
            continue;
        };
        let up = u32::from_str_radix(flags, 16).is_ok_and(|f| f & 0x1 != 0);
        if dest == "00000000" && mask == "00000000" && up {
            return Some(iface.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{parse_default_interface, pick_default_interface, DefaultCandidate};

    fn candidate(net: &str, if_name: &str, scoped: bool, metric: u32) -> DefaultCandidate {
        let net: ipnet::IpNet = net.parse().unwrap();
        DefaultCandidate {
            destination: net.addr(),
            prefix: net.prefix_len(),
            if_name: Some(if_name.to_string()),
            scoped,
            metric,
        }
    }

    /// A macOS table with two uplinks: the primary's default is unscoped,
    /// the secondary's carries `RTF_IFSCOPE` (`netstat -rn` flags `UGScg`
    /// vs `UGScIg`).
    #[test]
    fn macos_picks_the_unscoped_default() {
        let table = [
            candidate("0.0.0.0/0", "en0", true, 0),
            candidate("0.0.0.0/0", "en1", false, 0),
            candidate("127.0.0.0/8", "lo0", false, 0),
            candidate("192.168.0.0/24", "en1", false, 0),
            candidate("::/0", "utun0", false, 0),
        ];
        assert_eq!(pick_default_interface(table).as_deref(), Some("en1"));
    }

    /// Windows ranks defaults by route metric + interface metric; with
    /// automatic metrics the route metric ties at 0 and the interface
    /// decides.
    #[test]
    fn windows_picks_the_lowest_effective_metric() {
        let table = [
            candidate("0.0.0.0/0", "Wi-Fi", false, 35),
            candidate("0.0.0.0/0", "Ethernet", false, 25),
            candidate("::/0", "Ethernet 2", false, 5),
        ];
        assert_eq!(pick_default_interface(table).as_deref(), Some("Ethernet"));
        // A tie keeps table order.
        let tie = [
            candidate("0.0.0.0/0", "Ethernet", false, 25),
            candidate("0.0.0.0/0", "Wi-Fi", false, 25),
        ];
        assert_eq!(pick_default_interface(tie).as_deref(), Some("Ethernet"));
    }

    /// Issue #695, on the route-table platforms: a reload detects the
    /// interface while the running global listener's split defaults are
    /// installed. They share the default's destination (and on Windows may
    /// undercut its metric) but are `/1`, never `/0`.
    #[test]
    fn route_table_detection_skips_the_tun_split_default_routes() {
        let table = [
            candidate("0.0.0.0/1", "utun7", false, 0),
            candidate("128.0.0.0/1", "utun7", false, 0),
            candidate("::/1", "utun7", false, 0),
            candidate("8000::/1", "utun7", false, 0),
            candidate("0.0.0.0/0", "en0", false, 10),
        ];
        assert_eq!(
            pick_default_interface(table.clone()).as_deref(),
            Some("en0")
        );
        // Only the split routes left (no real default): nothing to bind to.
        let only_split = table.into_iter().filter(|r| r.prefix == 1);
        assert_eq!(pick_default_interface(only_split), None);
        // A default whose interface has no resolvable name is unusable.
        let nameless = DefaultCandidate {
            if_name: None,
            ..candidate("0.0.0.0/0", "x", false, 0)
        };
        assert_eq!(pick_default_interface([nameless]), None);
    }

    /// The real routing table, unprivileged: listing routes needs no root.
    /// A host without an IPv4 default route (offline CI) legitimately has
    /// nothing to detect; anything detected must be a real interface.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_detects_a_real_interface_from_the_live_table() {
        match super::default_interface() {
            Ok(name) => {
                let c_name = std::ffi::CString::new(name.clone()).unwrap();
                // SAFETY: `c_name` is a valid NUL-terminated string.
                let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
                assert_ne!(index, 0, "detected interface '{name}' must exist");
                println!("detected default interface: {name} (index {index})");
            }
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        }
    }

    const SAMPLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn picks_the_up_default_route_interface() {
        assert_eq!(parse_default_interface(SAMPLE).as_deref(), Some("eth0"));
    }

    #[test]
    fn ignores_down_defaults_and_empty_tables() {
        // Same default entry but with the UP bit clear → not a candidate.
        let down = SAMPLE.replace("00000000\t0101A8C0\t0003", "00000000\t0101A8C0\t0002");
        assert_eq!(parse_default_interface(&down), None);
        assert_eq!(parse_default_interface("Iface\tDestination\n"), None);
        assert_eq!(parse_default_interface(""), None);
    }

    /// Issue #695: a reload detects the interface while the running global
    /// listener's split defaults are installed, and the kernel lists
    /// `0.0.0.0/1` ahead of the real default (captured from a live table
    /// with `0.0.0.0/1` + `128.0.0.0/1` on the TUN).
    #[test]
    fn skips_the_tun_split_default_routes() {
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
meow-tun\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
meow-tun\t00000080\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";
        assert_eq!(parse_default_interface(table).as_deref(), Some("eth0"));
        // Only the split routes left (no real default): nothing to bind to.
        let only_split: String = table
            .lines()
            .filter(|l| !l.starts_with("eth0"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(parse_default_interface(&only_split), None);
    }
}
