//! Address setup for the Windows (Wintun) TUN adapter.
//!
//! Windows runs duplicate-address detection (DAD) on a new address and keeps
//! it *tentative* meanwhile; a tentative address cannot source packets, so
//! DNS and traffic right after startup would race it. tun-rs's builder adds
//! addresses that way, so on Windows the listener builds the device without
//! addresses and calls [`configure_addresses`]. That does what Wintun's own
//! example and wireguard-windows' `winipcfg` do: turn DAD off on the
//! interface, drop the family's addresses the adapter already carries (one
//! reopened after an unclean shutdown keeps its previous run's), and create
//! each address as Preferred.
//!
//! An address that another adapter still holds fails with
//! `ERROR_OBJECT_ALREADY_EXISTS`. That error is not swallowed: it reaches the
//! listener's retry loop, which moves on to a new adapter name and, from the
//! third attempt, a different address.

use std::io;
use std::net::IpAddr;
use std::ptr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, FreeMibTable, GetIpInterfaceEntry,
    GetUnicastIpAddressTable, InitializeUnicastIpAddressEntry, SetIpInterfaceEntry,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, ADDRESS_FAMILY, AF_INET, AF_INET6,
};

/// Give interface `index` exactly `ipv4`, plus `ipv6` when set, each usable
/// as soon as this returns.
pub(super) fn configure_addresses(
    index: u32,
    ipv4: Ipv4Net,
    ipv6: Option<Ipv6Net>,
) -> io::Result<()> {
    for network in std::iter::once(IpNet::V4(ipv4)).chain(ipv6.map(IpNet::V6)) {
        let family = if network.addr().is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        disable_dad(index, family)
            .and_then(|()| clear_addresses(index, family))
            .and_then(|()| add_address(index, network))
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("assign {network} to interface {index}: {e}"),
                )
            })?;
    }
    Ok(())
}

fn check(result: WIN32_ERROR) -> io::Result<()> {
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

/// Addresses added to the interface from now on skip DAD. An adapter that
/// outlives this process (and is reopened later) keeps the setting.
fn disable_dad(index: u32, family: ADDRESS_FAMILY) -> io::Result<()> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceIndex: index,
        ..Default::default()
    };
    // SAFETY: `row` is a valid, exclusively borrowed row keyed by family
    // and index, as the call expects.
    check(unsafe { GetIpInterfaceEntry(&raw mut row) })?;
    row.DadTransmits = 0;
    // `GetIpInterfaceEntry` can return a `SitePrefixLength` (notably for
    // IPv4) that `SetIpInterfaceEntry` then rejects.
    row.SitePrefixLength = 0;
    // SAFETY: `row` is the complete row read back above.
    check(unsafe { SetIpInterfaceEntry(&raw mut row) })
}

/// Delete the interface's `family` addresses, except IPv6 link-local ones,
/// which Windows configures itself.
fn clear_addresses(index: u32, family: ADDRESS_FAMILY) -> io::Result<()> {
    for row in interface_addresses(index, family)? {
        if row_ip(&row).is_some_and(is_link_local) {
            continue;
        }
        // SAFETY: `row` is a complete row IP Helper returned.
        let result = unsafe { DeleteUnicastIpAddressEntry(&raw const row) };
        // Already gone since the table was read: nothing to delete.
        if result != ERROR_NOT_FOUND {
            check(result)?;
        }
    }
    Ok(())
}

fn add_address(index: u32, network: IpNet) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` is a valid, exclusively borrowed row; the call sets
    // every field to its documented default.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };
    row.InterfaceIndex = index;
    row.OnLinkPrefixLength = network.prefix_len();
    // Usable at once instead of tentative.
    row.DadState = IpDadStatePreferred;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    match network.addr() {
        IpAddr::V4(ip) => {
            row.Address.Ipv4.sin_family = AF_INET;
            row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            row.Address.Ipv6.sin6_family = AF_INET6;
            row.Address.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    // SAFETY: `row` is fully initialised above.
    check(unsafe { CreateUnicastIpAddressEntry(&raw const row) })
}

/// The unicast address rows of `family` on interface `index`.
fn interface_addresses(
    index: u32,
    family: ADDRESS_FAMILY,
) -> io::Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    // SAFETY: `table` is a valid out-pointer; on success it points at a
    // table IP Helper allocated, freed below.
    let result = unsafe { GetUnicastIpAddressTable(family, &raw mut table) };
    // No address of the family on any interface.
    if result == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }
    check(result)?;
    // SAFETY: on success `table` holds `NumEntries` contiguous rows (`Table`
    // is a C flexible array member) and stays valid until `FreeMibTable`;
    // the rows are copied out before that.
    let rows = unsafe {
        let first = (&raw const (*table).Table).cast::<MIB_UNICASTIPADDRESS_ROW>();
        let rows: Vec<_> = std::slice::from_raw_parts(first, (*table).NumEntries as usize)
            .iter()
            .filter(|row| row.InterfaceIndex == index)
            .copied()
            .collect();
        FreeMibTable(table.cast());
        rows
    };
    Ok(rows)
}

/// The address a row carries; `None` for a family other than IPv4/IPv6.
fn row_ip(row: &MIB_UNICASTIPADDRESS_ROW) -> Option<IpAddr> {
    // SAFETY: every `SOCKADDR_INET` variant starts with the family field,
    // which says which variant the union holds.
    unsafe {
        match row.Address.si_family {
            AF_INET => Some(IpAddr::from(
                row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            )),
            AF_INET6 => Some(IpAddr::from(row.Address.Ipv6.sin6_addr.u.Byte)),
            _ => None,
        }
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::NL_DAD_STATE;

    /// `(address, prefix, DAD state)` of each address of `family` on
    /// interface `index`, IPv6 link-local ones aside.
    fn addresses(index: u32, family: ADDRESS_FAMILY) -> Vec<(IpAddr, u8, NL_DAD_STATE)> {
        interface_addresses(index, family)
            .expect("read the address table")
            .iter()
            .filter_map(|row| Some((row_ip(row)?, row.OnLinkPrefixLength, row.DadState)))
            .filter(|&(ip, ..)| !is_link_local(ip))
            .collect()
    }

    #[test]
    #[ignore = "creates a Wintun adapter, which needs Administrator; the windows CI job runs it"]
    fn addresses_are_preferred_and_replace_stale_ones() {
        let dll = super::super::wintun::resolve_wintun_dll().expect("locate wintun.dll");
        let dll = dll.to_string_lossy();
        let create = |name: &str| {
            tun_rs::DeviceBuilder::new()
                .name(name)
                .wintun_file(dll.to_string())
                .build_sync()
                .expect("create a Wintun adapter")
        };
        let device = create("meow-addr-test");
        let index = device.if_index().expect("adapter index");
        let v4: Ipv4Net = "198.18.250.1/30".parse().unwrap();
        let v6: Ipv6Net = "fdfe:dcba:9876::1/126".parse().unwrap();

        // The address the tun-rs builder path assigns: what an adapter
        // reopened after an unclean shutdown still carries.
        device
            .set_network_address(v4.addr(), v4.prefix_len(), None)
            .expect("assign through tun-rs");
        eprintln!(
            "tun-rs path left (address, prefix, DAD state 1=tentative 4=preferred): {:?}",
            addresses(index, AF_INET)
        );

        configure_addresses(index, v4, Some(v6)).expect("configure over the stale address");
        assert_eq!(
            addresses(index, AF_INET),
            [(IpAddr::V4(v4.addr()), 30, IpDadStatePreferred)]
        );
        assert_eq!(
            addresses(index, AF_INET6),
            [(IpAddr::V6(v6.addr()), 126, IpDadStatePreferred)]
        );

        // Reopened with a changed address, the adapter drops the old one.
        let changed: Ipv4Net = "198.18.250.5/30".parse().unwrap();
        configure_addresses(index, changed, Some(v6)).expect("configure a changed address");
        assert_eq!(
            addresses(index, AF_INET),
            [(IpAddr::V4(changed.addr()), 30, IpDadStatePreferred)]
        );

        // An address another adapter holds stays an error for the retry
        // loop to rotate past.
        let other = create("meow-addr-test-2");
        let err = configure_addresses(other.if_index().expect("adapter index"), changed, None)
            .expect_err("the address belongs to the first adapter");
        assert!(err.to_string().contains("os error 5010"), "{err}");
    }
}
