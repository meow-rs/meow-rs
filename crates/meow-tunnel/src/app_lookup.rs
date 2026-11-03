//! The app of a flow from this host, for the traffic ledger, looked up off
//! the flow's path.
//!
//! The ledger files each flow under the app that opened it. An Android VPN
//! names it in `Metadata::process` before dispatch. Elsewhere the owner of a
//! flow from this host (a loopback client of a listener, or this host's own
//! traffic through the TUN device or a transparent listener) is found with
//! the platform socket lookup PROCESS-NAME rules use, which can scan every
//! process (macOS). One thread runs the lookups in turn, so a burst of
//! flows costs one core at most and no flow waits for its app: its counters
//! keep what it carries until the app is known. Flows from other hosts (a
//! LAN gateway) have no app, and cost no scan.

use crate::statistics::ConnCounters;
use meow_common::process_lookup::PROCESS_LOOKUP_SUPPORTED;
use meow_common::{find_process, traffic_ledger, ConnType, Metadata, Network};
use smol_str::SmolStr;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};

/// Lookups queued at most; a flow past it is filed under no app.
const QUEUE: usize = 1024;

struct Lookup {
    network: Network,
    local: SocketAddr,
    counters: Arc<ConnCounters>,
}

/// The lookup thread's queue, started with the first lookup; `None` when
/// the thread could not start.
static LOOKUPS: OnceLock<Option<SyncSender<Lookup>>> = OnceLock::new();

/// The socket whose owner names `metadata`'s app, when this platform can
/// look it up and the flow may come from this host: from a loopback
/// address, or through an inbound that also carries other hosts' traffic,
/// where the lookup thread checks the source address first.
pub(crate) fn local_socket(metadata: &Metadata) -> Option<SocketAddr> {
    if !PROCESS_LOOKUP_SUPPORTED || metadata.src_port == 0 {
        return None;
    }
    // A dual-stack listener sees an IPv4 client as `::ffff:a.b.c.d`, which
    // is no loopback or interface address until it is mapped back.
    let ip = metadata.src_ip?.to_canonical();
    let maybe_local = ip.is_loopback()
        || matches!(
            metadata.conn_type,
            ConnType::Tun | ConnType::Redir | ConnType::TProxy
        );
    maybe_local.then(|| SocketAddr::new(ip, metadata.src_port))
}

/// The addresses of this host, the TUN device's included, as the lookup
/// thread tells a flow of this host's from a LAN client's.
#[derive(Default)]
struct LocalAddresses {
    /// The interfaces' addresses, read again as they change with the
    /// network: on a miss past [`MISS_AGE`] (an address just assigned),
    /// on a hit past [`HIT_AGE`] (an address given up, which a LAN client
    /// may hold now).
    #[cfg(target_os = "linux")]
    read: Option<(std::time::Instant, Vec<IpAddr>)>,
}

#[cfg(target_os = "linux")]
const MISS_AGE: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(target_os = "linux")]
const HIT_AGE: std::time::Duration = std::time::Duration::from_secs(10);

impl LocalAddresses {
    fn contains(&mut self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.assigned(ip)
    }

    /// On Linux, from the interface list: a bind would take any address
    /// with `ip_nonlocal_bind` set, as on some gateways.
    #[cfg(target_os = "linux")]
    fn assigned(&mut self, ip: IpAddr) -> bool {
        if let Some((at, addresses)) = &self.read {
            let listed = addresses.contains(&ip);
            let max_age = if listed { HIT_AGE } else { MISS_AGE };
            if at.elapsed() < max_age {
                return listed;
            }
        }
        let addresses = interface_addresses();
        let assigned = addresses.contains(&ip);
        self.read = Some((std::time::Instant::now(), addresses));
        assigned
    }

    /// Elsewhere, as a bind to it tells: no other system binds an address
    /// it does not have.
    #[cfg(not(target_os = "linux"))]
    fn assigned(&mut self, ip: IpAddr) -> bool {
        std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
    }
}

/// The addresses of this host's interfaces; none when they cannot be read.
#[cfg(target_os = "linux")]
fn interface_addresses() -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` points `list` at a list it allocated, freed below.
    if unsafe { libc::getifaddrs(&raw mut list) } != 0 {
        return addresses;
    }
    let mut entry = list;
    // SAFETY: every entry, and the address it points at, lives until
    // `freeifaddrs`; the family tells the address's type.
    while let Some(ifa) = unsafe { entry.as_ref() } {
        if let Some(addr) = unsafe { ifa.ifa_addr.as_ref() } {
            match i32::from(addr.sa_family) {
                libc::AF_INET => {
                    let addr = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                    addresses.push(IpAddr::from(addr.sin_addr.s_addr.to_ne_bytes()));
                }
                libc::AF_INET6 => {
                    let addr = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                    addresses.push(IpAddr::from(addr.sin6_addr.s6_addr).to_canonical());
                }
                _ => {}
            }
        }
        entry = ifa.ifa_next;
    }
    // SAFETY: `list` came from `getifaddrs` and is freed once.
    unsafe { libc::freeifaddrs(list) };
    addresses
}

/// Look up the app of the flow `counters` count, from `local`, and hand it
/// to them; no app when the queue is full.
pub(crate) fn submit(network: Network, local: SocketAddr, counters: &Arc<ConnCounters>) {
    let lookup = Lookup {
        network,
        local,
        counters: Arc::clone(counters),
    };
    let Some(lookups) = LOOKUPS.get_or_init(start) else {
        counters.resolve_app(SmolStr::default());
        return;
    };
    if let Err(TrySendError::Full(lookup) | TrySendError::Disconnected(lookup)) =
        lookups.try_send(lookup)
    {
        lookup.counters.resolve_app(SmolStr::default());
    }
}

fn start() -> Option<SyncSender<Lookup>> {
    let (lookups, queue) = sync_channel::<Lookup>(QUEUE);
    let thread = std::thread::Builder::new()
        .name("meow-app-lookup".into())
        .spawn(move || {
            let mut addresses = LocalAddresses::default();
            for Lookup {
                network,
                local,
                counters,
            } in queue
            {
                // No scan once the ledger or its apps went off, nor for a
                // LAN client's flow.
                let scan = traffic_ledger::enabled()
                    && traffic_ledger::apps()
                    && addresses.contains(local.ip());
                // A panic in a platform scan files the flow under no app
                // rather than leave its counters waiting.
                let info = scan
                    .then(|| std::panic::catch_unwind(move || find_process(network, local)))
                    .and_then(Result::ok)
                    .flatten();
                let app = info
                    .map(|info| traffic_ledger::app_name(&info.name, &info.path))
                    .unwrap_or_default();
                counters.resolve_app(app);
            }
        });
    match thread {
        Ok(_) => Some(lookups),
        Err(e) => {
            tracing::warn!("traffic ledger: no app lookups: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_hosts_addresses_are_looked_up() {
        let mut addresses = LocalAddresses::default();
        assert!(addresses.contains("127.0.0.1".parse().unwrap()));
        assert!(addresses.contains("::1".parse().unwrap()));
        // TEST-NET-3: assigned to no host.
        assert!(!addresses.contains("203.0.113.9".parse().unwrap()));
        let interface = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|socket| {
                socket.connect("192.0.2.1:9")?;
                socket.local_addr()
            })
            .map(|addr| addr.ip());
        if let Ok(ip) = interface {
            assert!(addresses.contains(ip), "{ip}, this host's");
        }

        let lan = Metadata {
            src_ip: Some("192.0.2.7".parse().unwrap()),
            src_port: 50_000,
            conn_type: ConnType::Http,
            ..Metadata::default()
        };
        assert_eq!(local_socket(&lan), None, "a LAN client of a listener");
        let mapped = Metadata {
            src_ip: Some("::ffff:127.0.0.1".parse().unwrap()),
            ..lan.clone()
        };
        let expected: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        assert_eq!(
            local_socket(&mapped),
            PROCESS_LOOKUP_SUPPORTED.then_some(expected),
            "an IPv4 client of a dual-stack listener"
        );
        let tun = Metadata {
            conn_type: ConnType::Tun,
            ..lan
        };
        assert_eq!(
            local_socket(&tun).is_some(),
            PROCESS_LOOKUP_SUPPORTED,
            "checked on the lookup thread"
        );
        let unbound = Metadata { src_port: 0, ..tun };
        assert_eq!(local_socket(&unbound), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_address_given_up_stops_counting_as_this_hosts() {
        use std::time::Instant;
        // TEST-NET-3: assigned to no host, as if this one gave it up.
        let given_up: IpAddr = "203.0.113.9".parse().unwrap();
        let mut addresses = LocalAddresses {
            read: Some((Instant::now(), vec![given_up])),
        };
        assert!(addresses.contains(given_up), "read just now");
        let Some(read_at) = Instant::now().checked_sub(HIT_AGE) else {
            return;
        };
        addresses.read = Some((read_at, vec![given_up]));
        assert!(!addresses.contains(given_up), "read again");
    }
}
