//! Address setup for the Windows (Wintun) TUN adapter.
//!
//! Windows runs duplicate-address detection (DAD) on a new address and
//! keeps it *tentative* meanwhile; a tentative address cannot source
//! packets, so DNS and traffic right after startup would race it.
//! tun-rs's builder adds addresses that way, so on Windows the listener
//! builds the device without addresses and calls [`configure_addresses`].
//! That does what Wintun's own example and wireguard-windows' `winipcfg`
//! do: turn DAD off on the interface, replace the addresses the adapter
//! already carries (one reopened after an unclean shutdown keeps its
//! previous run's), and create each configured one as Preferred.
//!
//! An address that another adapter still holds fails with
//! `ERROR_OBJECT_ALREADY_EXISTS`. That error is not swallowed: it reaches
//! the listener's retry loop, which moves on to a new adapter name and,
//! from the third attempt, a different address of both families — the
//! IPv4 one steps to the next `/30`, the IPv6 one to the next address
//! inside the configured subnet.
//!
//! A failed run rolls the adapter back to the addresses and the DAD
//! setting it had before. That matters for an adapter the run did not
//! create: tun-rs opens a same-named adapter instead of creating one —
//! or replaces it, when it is an orphaned leftover — and Wintun does not
//! delete a merely-opened adapter when it is closed, so the run then
//! replaces that adapter's addresses of both families (IPv6 ones even
//! when none is configured; link-local ones stay). The listener warns
//! when [`adapter_exists`] finds such an adapter; an adapter that
//! outlives the process also keeps `DadTransmits = 0`.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::ptr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, FreeMibTable, GetAdaptersAddresses,
    GetIpInterfaceEntry, GetUnicastIpAddressTable, InitializeUnicastIpAddressEntry,
    SetIpInterfaceEntry, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
    IP_ADAPTER_ADDRESSES_LH, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC,
};

/// Give interface `index` exactly `ipv4` and `ipv6` (the latter when
/// configured), each usable as soon as this returns: the configured
/// addresses end up Preferred, the stale ones — of both families, IPv6
/// link-local aside — are gone.
///
/// A failure rolls the interface back to the addresses and the DAD
/// setting it had, so an adapter the attempt merely opened is left as it
/// was found.
pub(super) fn configure_addresses(
    index: u32,
    ipv4: Ipv4Net,
    ipv6: Option<Ipv6Net>,
) -> io::Result<()> {
    // Each family's pre-run state, for the rollback on failure.
    let mut undo = Vec::new();
    for (family, network) in [
        (AF_INET, Some(IpNet::V4(ipv4))),
        (AF_INET6, ipv6.map(IpNet::V6)),
    ] {
        if let Err(e) = configure_family(index, family, network, &mut undo) {
            warn!("failed to configure interface {index}: {e}; rolling the adapter back");
            rollback(index, &undo);
            return Err(e);
        }
    }
    Ok(())
}

/// One family of [`configure_addresses`]: DAD off, the configured
/// address in as Preferred, the family's stale addresses gone. `None`
/// only clears the stale ones — DAD is left alone then, since nothing is
/// added.
///
/// The family's pre-run state goes into `undo` here; on any failure —
/// this family's own or a later one's — [`configure_addresses`] writes
/// it back.
fn configure_family(
    index: u32,
    family: ADDRESS_FAMILY,
    network: Option<IpNet>,
    undo: &mut Vec<FamilyUndo>,
) -> io::Result<()> {
    let previous = interface_addresses(index, family)
        .map_err(|e| step_error("failed to read the addresses".to_string(), index, e))?;
    // Addresses added from now on skip DAD; the setting the interface
    // had goes into the undo entry for the rollback.
    let old_transmits = match network {
        Some(network) => Some(set_dad_transmits(index, family, 0).map_err(|e| {
            step_error(
                format!("failed to turn duplicate-address detection off for {network}"),
                index,
                e,
            )
        })?),
        None => None,
    };
    let undo_slot = undo.len();
    undo.push(FamilyUndo {
        family,
        previous,
        old_transmits,
        added: None,
    });
    let Some(network) = network else {
        let removed = clear_stale(&undo[undo_slot].previous, None).map_err(|e| {
            step_error("failed to delete the stale addresses".to_string(), index, e)
        })?;
        debug!(
            "no {} address configured on interface {index}; removed {removed} stale address(es)",
            family_name(family),
        );
        return Ok(());
    };
    // A row already carrying the configured address is deleted first, so
    // the add cannot fail with `ERROR_OBJECT_ALREADY_EXISTS` and the
    // address comes back Preferred instead of staying tentative.
    for row in &undo[undo_slot].previous {
        if row_ip(row) == Some(network.addr()) {
            delete_row(row).map_err(|e| {
                step_error(
                    format!("failed to delete the old copy of {network}"),
                    index,
                    e,
                )
            })?;
        }
    }
    add_address(index, network)
        .map_err(|e| step_error(format!("failed to assign {network}"), index, e))?;
    undo[undo_slot].added = Some(network.addr());
    let removed = clear_stale(&undo[undo_slot].previous, Some(network.addr()))
        .map_err(|e| step_error("failed to delete the stale addresses".to_string(), index, e))?;
    debug!("interface {index} carries {network} as Preferred; removed {removed} stale address(es)",);
    Ok(())
}

/// One family's pre-run state, for the rollback after a failure.
struct FamilyUndo {
    family: ADDRESS_FAMILY,
    previous: Vec<MIB_UNICASTIPADDRESS_ROW>,
    /// The `DadTransmits` the interface had, when the run turned DAD
    /// off for it.
    old_transmits: Option<u32>,
    /// The address the run added, when the add made it in; the rollback
    /// removes it again.
    added: Option<IpAddr>,
}

/// Best-effort rollback after a failure: remove the address the run
/// managed to add and write the addresses and the DAD settings it
/// replaced back, so an adapter the run merely opened is left as it
/// was found — a leftover `added` would otherwise keep colliding with
/// the next attempt's own adapter (`ERROR_OBJECT_ALREADY_EXISTS`
/// crosses adapters). Restore failures are logged, not fatal: the
/// caller is already on a failure path.
fn rollback(index: u32, undo: &[FamilyUndo]) {
    for entry in undo {
        // The run's own add goes first: it can share the IP of a
        // `previous` row (a different prefix makes it a distinct
        // entry), so deleting it first lets the restored row come back
        // with its old prefix instead of colliding with the survivor.
        if let Some(ip) = entry.added {
            if let Err(e) = delete_added(index, ip) {
                warn!("failed to remove the added {ip} on interface {index}: {e}");
            }
        }
        for row in &entry.previous {
            let Some(ip) = row_ip(row) else { continue };
            if let Err(e) = restore_row(row) {
                if e.raw_os_error() != Some(ERROR_OBJECT_ALREADY_EXISTS as i32) {
                    warn!("failed to restore {ip} on interface {index}: {e}");
                }
            }
        }
        if let Some(transmits) = entry.old_transmits {
            if let Err(e) = set_dad_transmits(index, entry.family, transmits) {
                warn!("failed to restore the DAD setting on interface {index}: {e}");
            }
        }
    }
}

/// Set the interface's `DadTransmits` and return the value it had. `0`
/// disables duplicate-address detection for addresses added from now on;
/// an adapter that outlives this process (and is reopened later) keeps
/// the setting.
fn set_dad_transmits(index: u32, family: ADDRESS_FAMILY, transmits: u32) -> io::Result<u32> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceIndex: index,
        ..Default::default()
    };
    // SAFETY: `row` is a valid, exclusively borrowed row keyed by family
    // and index, as the call expects.
    check(unsafe { GetIpInterfaceEntry(&raw mut row) })?;
    let previous = row.DadTransmits;
    row.DadTransmits = transmits;
    // `GetIpInterfaceEntry` can return a `SitePrefixLength` (notably for
    // IPv4) that `SetIpInterfaceEntry` then rejects.
    row.SitePrefixLength = 0;
    // SAFETY: `row` is the complete row read back above.
    check(unsafe { SetIpInterfaceEntry(&raw mut row) })?;
    Ok(previous)
}

/// Delete every address in `previous` except IPv6 link-local ones and
/// `keep` (the address this run adds), returning how many went.
fn clear_stale(previous: &[MIB_UNICASTIPADDRESS_ROW], keep: Option<IpAddr>) -> io::Result<usize> {
    let mut removed = 0;
    for row in previous {
        let Some(ip) = row_ip(row) else { continue };
        if Some(ip) == keep || is_link_local(ip) {
            continue;
        }
        delete_row(row)?;
        removed += 1;
    }
    Ok(removed)
}

/// Delete one address row the interface carries.
fn delete_row(row: &MIB_UNICASTIPADDRESS_ROW) -> io::Result<()> {
    // SAFETY: `row` is a complete row IP Helper returned; the call only
    // reads it.
    let result = unsafe { DeleteUnicastIpAddressEntry(&raw const *row) };
    // Whatever Microsoft's docs attribute `ERROR_NOT_FOUND` to (their
    // wording says a missing interface), the entry is gone from the
    // interface's point of view; a genuinely vanished interface makes
    // the following calls fail loudly instead.
    if result != ERROR_NOT_FOUND {
        check(result)?;
    }
    Ok(())
}

/// Delete the address `ip` this run added to interface `index`. Unlike
/// [`delete_row`], which replays a row IP Helper returned, the row is
/// fabricated here — the delete keys on (interface, address) alone.
fn delete_added(index: u32, ip: IpAddr) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` is a valid, exclusively borrowed row; the call sets
    // every field to its documented default.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };
    row.InterfaceIndex = index;
    match ip {
        IpAddr::V4(ip) => {
            row.Address.Ipv4.sin_family = AF_INET;
            row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            row.Address.Ipv6.sin6_family = AF_INET6;
            row.Address.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    // SAFETY: `row` carries the members the delete keys on — `Address`
    // and `InterfaceIndex` — both set above. As in `delete_row`, a
    // not-found result already is the end state wanted here.
    let result = unsafe { DeleteUnicastIpAddressEntry(&raw const row) };
    if result != ERROR_NOT_FOUND {
        check(result)?;
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

/// Re-create an address the failed run deleted, from the row IP Helper
/// returned. Best effort, on the rollback path only: DAD is still off
/// (or was, for a family whose run went no further than a disabled DAD),
/// so the address returns as Preferred instead of tentative. The
/// snapshot's lifetimes and `SkipAsSource` come back with it, so the
/// restored row matches what was found; `PrefixOrigin`/`SuffixOrigin`
/// are output-only members and keep the defaults the initialize call
/// wrote.
fn restore_row(row: &MIB_UNICASTIPADDRESS_ROW) -> io::Result<()> {
    let mut fresh = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `fresh` is a valid, exclusively borrowed row; the call
    // sets every field to its documented default.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut fresh) };
    fresh.Address = row.Address;
    fresh.InterfaceIndex = row.InterfaceIndex;
    fresh.OnLinkPrefixLength = row.OnLinkPrefixLength;
    fresh.DadState = IpDadStatePreferred;
    fresh.ValidLifetime = row.ValidLifetime;
    fresh.PreferredLifetime = row.PreferredLifetime;
    fresh.SkipAsSource = row.SkipAsSource;
    // SAFETY: `fresh` is fully initialised above.
    check(unsafe { CreateUnicastIpAddressEntry(&raw const fresh) })
}

/// Whether an adapter with the friendly name `name` already exists.
///
/// The listener warns before building when one does: tun-rs opens a
/// same-named, non-orphaned adapter instead of creating one — an
/// orphaned leftover it replaces — and Wintun does not delete a
/// merely-opened adapter when it is closed, so the run then replaces
/// addresses on an adapter this startup did not create. The check cannot
/// tell the two cases apart (the orphan test is tun-rs-private), so the
/// warning can fire on a name that ends up freshly created.
pub(super) fn adapter_exists(name: &str) -> io::Result<bool> {
    // Only the names are read, and a leftover adapter from an unclean
    // shutdown may not be operational, so ask for every adapter.
    const FLAGS: u32 = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_INCLUDE_ALL_INTERFACES;
    // The buffer size the API docs recommend starting at; the loop grows
    // it while the API reports `ERROR_BUFFER_OVERFLOW`. A u64 store keeps
    // the `IP_ADAPTER_ADDRESSES_LH` list the call writes into it 8-aligned,
    // like the API's own allocation — the struct carries u64 members.
    let mut size: u32 = 15000;
    let mut buf = vec![0u64; size as usize / 8 + 1];
    for _ in 0..4 {
        // SAFETY: `buf` is 8-aligned by its element type, holds at least
        // `size` initialised bytes, and outlives the call; `size` is a
        // valid in/out pointer; on overflow the call reports the size it
        // needs there.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                FLAGS,
                ptr::null(),
                buf.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            buf.resize(size as usize / 8 + 1, 0);
            continue;
        }
        check(result)?;
        return Ok(table_has_adapter(&buf, name));
    }
    Err(io::Error::other(
        "GetAdaptersAddresses overflowed four buffers in a row",
    ))
}

/// Whether the linked list `GetAdaptersAddresses` built in `buf` holds
/// an adapter named `name`. The u64 element type conveys the alignment
/// the entries need — the struct carries u64 members.
fn table_has_adapter(buf: &[u64], name: &str) -> bool {
    // SAFETY: `buf` is 8-aligned by its element type; on success the
    // buffer starts with the linked list the call built, valid for as
    // long as the buffer is; the walk only reads it.
    let mut next = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !next.is_null() {
        // SAFETY: `next` points at one of the list's entries.
        let adapter = unsafe { &*next };
        // SAFETY: `FriendlyName` is a NUL-terminated string inside the
        // same buffer.
        if unsafe { name_eq(adapter.FriendlyName.cast_const(), name) } {
            return true;
        }
        next = adapter.Next;
    }
    false
}

/// Whether a NUL-terminated UTF-16 string equals `name`.
///
/// # Safety
///
/// `s` must point at a NUL-terminated UTF-16 string.
unsafe fn name_eq(s: *const u16, name: &str) -> bool {
    if s.is_null() {
        return false;
    }
    let mut p = s;
    // SAFETY: `p` starts on the string and only advances while the
    // units matched, so the walk stays on it; the trailing `0` compares
    // against the string's own terminator, so the walk never leaves it.
    unsafe {
        for unit in name.encode_utf16().chain(Some(0)) {
            if *p != unit {
                return false;
            }
            p = p.add(1);
        }
    }
    true
}

/// Wrap an error from one step of [`configure_addresses`] with what the
/// step was, keeping the original as the `source`: its `raw_os_error`
/// stays reachable by walking the chain, so a caller can still tell
/// `ERROR_OBJECT_ALREADY_EXISTS` (a conflicted address) from other
/// failures.
#[derive(Debug)]
struct StepError {
    step: String,
    index: u32,
    source: io::Error,
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            step,
            index,
            source,
        } = self;
        write!(f, "{step} on interface {index}: {source}")
    }
}

impl std::error::Error for StepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn step_error(step: String, index: u32, e: io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        StepError {
            step,
            index,
            source: e,
        },
    )
}

fn check(result: WIN32_ERROR) -> io::Result<()> {
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

fn family_name(family: ADDRESS_FAMILY) -> &'static str {
    match family {
        AF_INET => "IPv4",
        _ => "IPv6",
    }
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
    // SAFETY: on success `table` points at a buffer IP Helper allocated:
    // `NumEntries` rows contiguous after the first one (`Table` is a
    // 1-element placeholder array in windows-sys, never taken as a
    // reference here — the first row's address comes from `&raw const`).
    // The buffer stays valid until `FreeMibTable`; the rows are copied
    // out before that.
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
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use windows_sys::Win32::Networking::WinSock::NL_DAD_STATE;

    use super::*;

    /// `(address, prefix, DAD state)` of each address of `family` on
    /// interface `index`, link-local ones aside — the IPv6 `fe80::/10`
    /// range and the IPv4 APIPA range alike, either of which the OS may
    /// add on its own and none of the assertions here has a stake in.
    fn addresses(index: u32, family: ADDRESS_FAMILY) -> Vec<(IpAddr, u8, NL_DAD_STATE)> {
        interface_addresses(index, family)
            .expect("read the address table")
            .iter()
            .filter_map(|row| Some((row_ip(row)?, row.OnLinkPrefixLength, row.DadState)))
            .filter(|&(ip, ..)| match ip {
                IpAddr::V4(v4) => !v4.is_link_local(),
                IpAddr::V6(v6) => !v6.is_unicast_link_local(),
            })
            .collect()
    }

    /// The interface carries each of `expected` with its configured
    /// prefix, as Preferred. Presence-shaped, not an exact set: an
    /// address the OS adds on its own is none of these assertions'
    /// business, while a stale one that survived the replacement still
    /// shows up as a missing expectation.
    fn assert_preferred(index: u32, family: ADDRESS_FAMILY, expected: &[(IpAddr, u8)]) {
        let carried = addresses(index, family);
        for (ip, prefix) in expected {
            assert!(
                carried.contains(&(*ip, *prefix, IpDadStatePreferred)),
                "interface {index} does not carry {ip}/{prefix} as Preferred; it has {carried:?}"
            );
        }
    }

    /// The interface no longer carries any of `gone`.
    fn assert_gone(index: u32, family: ADDRESS_FAMILY, gone: &[IpAddr]) {
        let carried = addresses(index, family);
        for ip in gone {
            assert!(
                !carried.iter().any(|(addr, ..)| addr == ip),
                "interface {index} still carries {ip}; it has {carried:?}"
            );
        }
    }

    /// The OS error code of `err` — wherever along the `source` chain it
    /// ended up. `step_error` wraps the original error, so the top-level
    /// `raw_os_error` is `None` and the code has to be picked out of the
    /// chain instead of out of the Display text, which the OS localizes.
    fn raw_os_error_of(err: &io::Error) -> Option<i32> {
        let mut current: &(dyn std::error::Error + 'static) = err;
        loop {
            if let Some(code) = current
                .downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error)
            {
                return Some(code);
            }
            current = current.source()?;
        }
    }

    #[test]
    fn wrapped_step_error_keeps_the_os_code_reachable() {
        let raw = io::Error::from_raw_os_error(ERROR_OBJECT_ALREADY_EXISTS as i32);
        let wrapped = step_error("failed to assign 198.18.250.1/30".to_string(), 7, raw);
        assert_eq!(wrapped.raw_os_error(), None);
        assert_eq!(
            raw_os_error_of(&wrapped),
            Some(ERROR_OBJECT_ALREADY_EXISTS as i32)
        );
    }

    #[test]
    fn adapter_exists_matches_the_whole_friendly_name_only() {
        // A hand-built `GetAdaptersAddresses` list — two entries linked
        // through `Next`, the way the API builds it — exercising the
        // adapter probe the listener warns with, without needing a real
        // adapter. The backing store is u64-aligned, like the API's own
        // allocation, so the struct written into it stays aligned.
        let mut names: Vec<Vec<u16>> = ["meow-addr-test", "meow-addr-test-2"]
            .iter()
            .map(|name| name.encode_utf16().chain(Some(0)).collect())
            .collect();
        let entry_size = std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>();
        let words = 2 * entry_size.div_ceil(std::mem::size_of::<u64>()) + 4;
        let mut store: Vec<u64> = vec![0; words];
        // SAFETY: `first`/`second` point at the two entries the store is
        // sized for — it is u64-aligned, like the API's own allocation —
        // and it outlives this function, as do the name buffers the
        // assertions read through the entries.
        unsafe {
            let first = store.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let second = first.byte_add(entry_size);
            (*first).Next = second;
            (*first).FriendlyName = names[0].as_mut_ptr();
            (*second).FriendlyName = names[1].as_mut_ptr();
        }
        assert!(table_has_adapter(&store, "meow-addr-test"));
        assert!(table_has_adapter(&store, "meow-addr-test-2"));
        // The whole friendly name has to match — a prefix or a
        // superstring of one entry's name must not hit.
        assert!(!table_has_adapter(&store, "meow-addr-tes"));
        assert!(!table_has_adapter(&store, "meow-addr-test-22"));
    }

    /// A test adapter's name: the listener's own naming scheme
    /// (`device_name_for_attempt`, `tun/mod.rs`) over a per-process
    /// base, so a leftover from a killed run — Wintun removes an adapter
    /// it created only on a clean close — can never be reopened and
    /// reconfigured by mistake.
    fn adapter_name(tag: &str) -> String {
        let base = format!("meow-addr-test-{tag}-{}", std::process::id());
        crate::tun::device_name_for_attempt(Some(&base), 0).unwrap()
    }

    /// An adapter built the way the listener's `spawn_blocking` closure
    /// builds one (`tun/mod.rs`): the configured mtu, the pinned
    /// `wintun.dll`, logging on — and no addresses, which on Windows the
    /// listener assigns itself through [`configure_addresses`]
    /// (`build_async` wraps the same blocking setup; this stays
    /// synchronous).
    fn listener_adapter(dll: &str, name: &str) -> tun_rs::SyncDevice {
        tun_rs::DeviceBuilder::new()
            .mtu(1500)
            .name(name)
            .wintun_file(dll.to_string())
            .wintun_log(true)
            .build_sync()
            .expect("create a Wintun adapter the way the listener does")
    }

    #[test]
    #[ignore = "creates a real Wintun adapter: needs Administrator, the wintun.dll sidecar (or the copy embedded in the binary), and the Wintun driver; the windows CI job runs it"]
    fn addresses_are_preferred_and_replace_stale_ones() {
        let dll = super::super::wintun::resolve_wintun_dll().expect("locate wintun.dll");
        let dll = dll.to_string_lossy();
        let name = adapter_name("preferred");
        assert!(
            !adapter_exists(&name).expect("probe the adapter table"),
            "no adapter called '{name}' should exist yet"
        );
        let device = listener_adapter(&dll, &name);
        assert!(
            adapter_exists(&name).expect("probe the adapter table"),
            "the adapter just created should be findable by its friendly name"
        );
        let index = device.if_index().expect("adapter index");
        let v4: Ipv4Net = "198.18.250.1/30".parse().unwrap();
        let v6: Ipv6Net = "fdfe:dcba:9876::1/126".parse().unwrap();

        // The address the tun-rs builder path assigns (its
        // `set_network_address`): what an adapter reopened after an
        // unclean shutdown still carries.
        device
            .set_network_address(v4.addr(), v4.prefix_len(), None)
            .expect("assign through tun-rs");
        eprintln!(
            "tun-rs path left (address, prefix, DAD state 1=tentative 4=preferred): {:?}",
            addresses(index, AF_INET)
        );

        // The listener's own call shape (tun/mod.rs).
        configure_addresses(
            index,
            Ipv4Net::new_assert(v4.addr(), v4.prefix_len()),
            Some(v6),
        )
        .expect("configure over the stale address");
        assert_preferred(index, AF_INET, &[(IpAddr::V4(v4.addr()), v4.prefix_len())]);
        assert_preferred(index, AF_INET6, &[(IpAddr::V6(v6.addr()), v6.prefix_len())]);

        // Reopened with a changed address, the adapter drops the old one.
        let changed: Ipv4Net = "198.18.250.5/30".parse().unwrap();
        configure_addresses(index, changed, Some(v6)).expect("configure a changed address");
        assert_preferred(
            index,
            AF_INET,
            &[(IpAddr::V4(changed.addr()), changed.prefix_len())],
        );
        assert_gone(index, AF_INET, &[IpAddr::V4(v4.addr())]);

        // DAD is off, not merely optimistic: the setting reads back as
        // zero, and the addresses survive — Preferred — past the time
        // the OS's duplicate-address detection would have run.
        assert_eq!(
            set_dad_transmits(index, AF_INET, 0).expect("read DadTransmits back"),
            0
        );
        assert_eq!(
            set_dad_transmits(index, AF_INET6, 0).expect("read DadTransmits back"),
            0
        );
        std::thread::sleep(Duration::from_millis(3500));
        assert_preferred(
            index,
            AF_INET,
            &[(IpAddr::V4(changed.addr()), changed.prefix_len())],
        );
        assert_preferred(index, AF_INET6, &[(IpAddr::V6(v6.addr()), v6.prefix_len())]);
    }

    #[test]
    #[ignore = "creates a real Wintun adapter: needs Administrator, the wintun.dll sidecar (or the copy embedded in the binary), and the Wintun driver; the windows CI job runs it"]
    fn inet6_none_replaces_stale_addresses_of_both_families() {
        let dll = super::super::wintun::resolve_wintun_dll().expect("locate wintun.dll");
        let dll = dll.to_string_lossy();
        let name = adapter_name("no-inet6");
        let device = listener_adapter(&dll, &name);
        let index = device.if_index().expect("adapter index");
        let v4: Ipv4Net = "198.18.250.9/30".parse().unwrap();
        let v6: Ipv6Net = "fdfe:dcba:9876::9/126".parse().unwrap();

        // A previous run with inet6 configured left both families behind.
        configure_addresses(
            index,
            Ipv4Net::new_assert(v4.addr(), v4.prefix_len()),
            Some(v6),
        )
        .expect("configure with an inet6 address");
        assert_preferred(index, AF_INET, &[(IpAddr::V4(v4.addr()), v4.prefix_len())]);
        assert_preferred(index, AF_INET6, &[(IpAddr::V6(v6.addr()), v6.prefix_len())]);

        // Reopened with inet6 dropped from the config: the stale IPv6
        // address goes the way of the stale IPv4 one — the adapter ends
        // up with exactly what the config says.
        let changed: Ipv4Net = "198.18.250.13/30".parse().unwrap();
        configure_addresses(index, changed, None).expect("configure without inet6");
        assert_preferred(
            index,
            AF_INET,
            &[(IpAddr::V4(changed.addr()), changed.prefix_len())],
        );
        assert_gone(index, AF_INET, &[IpAddr::V4(v4.addr())]);
        assert_gone(index, AF_INET6, &[IpAddr::V6(v6.addr())]);
        assert!(
            addresses(index, AF_INET6).is_empty(),
            "without inet6 configured the adapter should carry no IPv6 address; it has {:?}",
            addresses(index, AF_INET6)
        );
    }

    #[test]
    #[ignore = "creates a real Wintun adapter: needs Administrator, the wintun.dll sidecar (or the copy embedded in the binary), and the Wintun driver; the windows CI job runs it"]
    fn conflicted_address_fails_and_leaves_the_adapter_as_found() {
        let dll = super::super::wintun::resolve_wintun_dll().expect("locate wintun.dll");
        let dll = dll.to_string_lossy();
        let device = listener_adapter(&dll, &adapter_name("conflict-a"));
        let other = listener_adapter(&dll, &adapter_name("conflict-b"));
        let index = device.if_index().expect("adapter index");
        let other_index = other.if_index().expect("adapter index");
        let owned: Ipv4Net = "198.18.250.17/30".parse().unwrap();
        let taken: Ipv4Net = "198.18.250.21/30".parse().unwrap();

        // What each adapter carries before the conflict: the state a
        // failed attempt has to leave the reconfigured one in.
        configure_addresses(
            index,
            Ipv4Net::new_assert(owned.addr(), owned.prefix_len()),
            None,
        )
        .expect("configure the first adapter");
        configure_addresses(
            other_index,
            Ipv4Net::new_assert(taken.addr(), taken.prefix_len()),
            None,
        )
        .expect("configure the second adapter");

        // `taken` still belongs to the second adapter: the add fails,
        // the conflict stays tellable apart along the source chain, and
        // the failed attempt leaves the first adapter as it was found.
        let err = configure_addresses(index, taken, None)
            .expect_err("the address belongs to the other adapter");
        assert_eq!(
            raw_os_error_of(&err),
            Some(ERROR_OBJECT_ALREADY_EXISTS as i32),
            "{err}"
        );
        assert_gone(index, AF_INET, &[IpAddr::V4(taken.addr())]);
        assert_preferred(
            index,
            AF_INET,
            &[(IpAddr::V4(owned.addr()), owned.prefix_len())],
        );
        assert_preferred(
            other_index,
            AF_INET,
            &[(IpAddr::V4(taken.addr()), taken.prefix_len())],
        );

        // The retry loop's answer to a conflict (`tun/mod.rs`): from the
        // third attempt a different address — IPv4 steps 4 addresses up
        // from the configured one — on a fresh adapter name. Here the
        // first adapter takes the rotated one and comes up.
        let rotated = Ipv4Net::new_assert(
            Ipv4Addr::from(u32::from(taken.addr()) + 4),
            taken.prefix_len(),
        );
        configure_addresses(index, rotated, None).expect("configure the rotated address");
        assert_preferred(
            index,
            AF_INET,
            &[(IpAddr::V4(rotated.addr()), rotated.prefix_len())],
        );
        assert_gone(index, AF_INET, &[IpAddr::V4(owned.addr())]);
    }
}
