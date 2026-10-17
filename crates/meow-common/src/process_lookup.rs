//! Platform-specific lookup: which local process owns a given socket?
//!
//! The rule engine calls [`find_process`] for PROCESS-NAME / PROCESS-PATH /
//! UID rules. It receives the connection's local (client-side) address and
//! returns the owning process, if any. Returns `None` on platforms that are
//! not yet supported (everything except Linux, macOS and Windows).
//!
//! An embedder whose inbound can name a flow's owner itself (an Android VPN)
//! fills those `Metadata` fields before dispatch instead, and says so with
//! [`enable_inbound_process_info`].

use crate::network::Network;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

/// `true` on platforms with a real [`find_process`] implementation
/// (Linux / macOS / Windows); `false` where it is a stub that always
/// returns `None`. Rule types use this to gate `should_find_process`
/// demands and `never_matches` deadness — keep the cfg set in sync with
/// the `platform` modules below when porting to a new OS.
pub const PROCESS_LOOKUP_SUPPORTED: bool = cfg!(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows"
));

/// Set by [`enable_inbound_process_info`].
static INBOUND_PROCESS_INFO: AtomicBool = AtomicBool::new(false);

/// Declare that this embedder's inbound fills `Metadata::process`,
/// `process_path` and/or `uid` itself before dispatch.
///
/// For platforms where [`find_process`] is a stub but the embedder can
/// still name a flow's owner: an Android VPN asks
/// `ConnectivityManager.getConnectionOwnerUid` with the app socket's
/// original 4-tuple, which only its TUN inbound sees (fake-IP handling
/// drops the original destination before rule matching). With it,
/// PROCESS-NAME / PROCESS-PATH / UID rules stay live there and match the
/// supplied fields as they are; without it they are folded dead (#625).
///
/// Liveness is decided when rules are built, so call this before the first
/// config load. One-way: rules built while it was on would stay live anyway.
pub fn enable_inbound_process_info() {
    INBOUND_PROCESS_INFO.store(true, Ordering::Relaxed);
}

/// Whether `Metadata::process` / `process_path` can ever be populated here:
/// by a native [`find_process`], or by an inbound that supplies them
/// ([`enable_inbound_process_info`]). Gates PROCESS-NAME / PROCESS-PATH
/// deadness; the demand for a native lookup stays on
/// [`PROCESS_LOOKUP_SUPPORTED`].
pub fn process_info_available() -> bool {
    PROCESS_LOOKUP_SUPPORTED || INBOUND_PROCESS_INFO.load(Ordering::Relaxed)
}

/// Whether UID rules can match here: on Linux by policy (Class B per
/// ADR-0002; the macOS lookup fills `uid` too, but the rule stays dead
/// there), or wherever an inbound supplies `uid`
/// ([`enable_inbound_process_info`]).
pub fn uid_info_available() -> bool {
    cfg!(target_os = "linux") || INBOUND_PROCESS_INFO.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub name: String,
    pub path: String,
    pub uid: Option<u32>,
}

/// Look up the process that owns the socket bound to `local_addr`. `local_addr`
/// is the socket endpoint as seen by meow-rs's inbound — i.e. the client's
/// source address when it connected to the proxy listener.
///
/// This is a synchronous scan of OS tables (`/proc`, `libproc`,
/// `GetExtended*Table`); callers on an async runtime should prefer
/// [`find_process_async`], which offloads it to the blocking pool.
pub fn find_process(network: Network, local_addr: SocketAddr) -> Option<ProcessInfo> {
    platform::find_process(network, local_addr)
}

/// Async counterpart of [`find_process`]: the platform scan is synchronous
/// and can cost milliseconds on hosts with large socket tables — running it
/// on a Tokio worker stalls every task sharing that worker (issue #515).
/// Offloads to the blocking pool; the Linux impl additionally serves most
/// lookups from short-TTL caches, so the offload is usually a map hit.
pub async fn find_process_async(network: Network, local_addr: SocketAddr) -> Option<ProcessInfo> {
    match tokio::task::spawn_blocking(move || find_process(network, local_addr)).await {
        Ok(info) => info,
        Err(e) => {
            // spawn_blocking tasks are never cancelled, so a JoinError is a
            // panic in the platform scan — surface it, then report no match
            // (rules fall through as if the process were unknown).
            tracing::warn!("process lookup task failed: {e}");
            None
        }
    }
}

/// Test hook for **dependent** crates' test binaries: they build this
/// crate without `cfg(test)`, so the Linux `/proc/net` socket-table TTL
/// cache is live there — and a snapshot populated by a sibling test can
/// omit a socket the test bound moments earlier (the "passes alone,
/// fails in a full run" flake). Call once at test start to force a fresh
/// parse on every lookup. A no-op elsewhere: non-Linux platforms hold no
/// socket-table cache, and this crate's own `cfg(test)` build already
/// bypasses it.
#[doc(hidden)]
pub fn disable_socket_table_cache() {
    #[cfg(target_os = "linux")]
    platform::disable_socket_table_cache();
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Network, ProcessInfo, SocketAddr};
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::fs;
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};
    use tracing::trace;

    /// Set by the crate-level `disable_socket_table_cache` test hook. A
    /// dependent crate's test binary builds this module without
    /// `cfg(test)`, so the real `SOCK_TABLES` TTL path below would be live
    /// and a snapshot populated by a sibling test can omit a socket the
    /// test bound moments earlier — the dependent-crate full-run flake.
    static DISABLE_TABLE_CACHE: AtomicBool = AtomicBool::new(false);

    /// Backs [`super::disable_socket_table_cache`]. Relaxed is sufficient:
    /// the flag is monotonic (never re-set to false) and every reader is
    /// ordered after the test's store anyway — same-thread program order
    /// for the sync tests, spawn's synchronize-with edge for
    /// `find_process_async`.
    pub fn disable_socket_table_cache() {
        DISABLE_TABLE_CACHE.store(true, Ordering::Relaxed);
    }

    /// Short-TTL caches bounding the synchronous /proc work (issue #515).
    ///
    /// - `SOCK_TABLES`: one parsed `/proc/net/{tcp,tcp6,udp,udp6}` shared by
    ///   every lookup within `TABLE_TTL`, so a burst of concurrent
    ///   connections pays for a single scan instead of one scan each.
    /// - `INODE_MAP`: the `/proc/<pid>/fd` walk is the expensive half; cached
    ///   per inode for `INODE_TTL`.
    ///
    /// Staleness contract: a hit reports the owner of the endpoint as of at
    /// most TTL ago. The misattribution vector is ephemeral-port reuse —
    /// within `TABLE_TTL` a re-bound port can map to the *closed* socket's
    /// inode, so `INODE_MAP` then returns the previous owner for up to
    /// ~100 ms (sockfs inode numbers are monotonic and never recycled, so
    /// the inode→pid entry itself stays accurate while the inode lives).
    /// A transient `/proc/<pid>/fd` read failure caches `None` for
    /// `INODE_TTL`, suppressing attribution for up to 1 s.
    #[cfg(not(test))]
    const TABLE_TTL: Duration = Duration::from_millis(100);
    const INODE_TTL: Duration = Duration::from_secs(1);
    /// Bound on cached inode entries; cleared wholesale past this so a host
    /// with extreme socket churn cannot grow the map without bound.
    const INODE_CACHE_CAP: usize = 4096;

    /// port → list of (local addr, inode, uid). Keyed by port because the
    /// target port filters nearly every row out before address matching.
    type SockTable = HashMap<u16, Vec<(IpAddr, u64, u32)>>;

    #[cfg(not(test))]
    struct CachedTable {
        at: Instant,
        map: std::sync::Arc<SockTable>,
    }

    /// inode → (cached at, lookup result) — `None` caches a miss so a
    /// short-lived socket's vanished inode isn't re-scanned every TTL.
    type InodeCache = HashMap<u64, (Instant, Option<(u32, String, String)>)>;

    /// Slots indexed `[network as usize][is_ipv6 as usize]`.
    #[cfg(not(test))]
    static SOCK_TABLES: OnceLock<Mutex<[[Option<CachedTable>; 2]; 2]>> = OnceLock::new();
    static INODE_MAP: OnceLock<Mutex<InodeCache>> = OnceLock::new();

    pub fn find_process(network: Network, local: SocketAddr) -> Option<ProcessInfo> {
        let (table_idx, path, ipv6) = match (network, local.is_ipv4()) {
            (Network::Tcp, true) => (0, "/proc/net/tcp", false),
            (Network::Tcp, false) => (0, "/proc/net/tcp6", true),
            (Network::Udp, true) => (1, "/proc/net/udp", false),
            (Network::Udp, false) => (1, "/proc/net/udp6", true),
        };

        let table = sock_table(table_idx, path, ipv6);
        let (inode, uid) = table
            .get(&local.port())
            .into_iter()
            .flatten()
            .find(|(addr, _, _)| addr_matches(*addr, local.ip()))
            .map(|(_, inode, uid)| (*inode, *uid))?;
        trace!(inode, uid, "process_lookup: matched /proc/net entry");
        let (_pid, name, exe) = find_pid_by_inode_cached(inode)?;
        Some(ProcessInfo {
            name,
            path: exe,
            uid: Some(uid),
        })
    }

    /// Return the socket table for `(network, family)`, refreshing it from
    /// /proc when the cached snapshot is older than `TABLE_TTL`. The map is
    /// `Arc`-shared so a hit clones a pointer, not the table. A failed read
    /// caches an empty table so the TTL also bounds retry pressure on a
    /// host where /proc is unreadable (lookups report "no process", same
    /// observable result as before).
    fn sock_table(idx: usize, path: &str, ipv6: bool) -> Arc<SockTable> {
        // Unit tests bind fresh sockets and look them up immediately — a
        // TTL'd snapshot taken by a parallel test would be racy, so test
        // builds always re-parse.
        #[cfg(test)]
        {
            let _ = idx;
            Arc::new(parse_proc_net(path, ipv6).unwrap_or_default())
        }
        #[cfg(not(test))]
        {
            if DISABLE_TABLE_CACHE.load(Ordering::Relaxed) {
                return Arc::new(parse_proc_net(path, ipv6).unwrap_or_default());
            }
            let tables = SOCK_TABLES.get_or_init(|| Mutex::new(Default::default()));
            let mut guard = tables.lock();
            let slot = &mut guard[idx][usize::from(ipv6)];
            let stale = slot.as_ref().is_none_or(|t| t.at.elapsed() > TABLE_TTL);
            if stale {
                *slot = Some(CachedTable {
                    at: Instant::now(),
                    map: Arc::new(parse_proc_net(path, ipv6).unwrap_or_default()),
                });
            }
            Arc::clone(&slot.as_ref().expect("slot just populated").map)
        }
    }

    /// Parse a `/proc/net/{tcp,udp}{,6}` table into a port-keyed map.
    /// Returns `None` when the file cannot be read at all (treated as a
    /// lookup miss, same as before — the caller reports "no process").
    pub(crate) fn parse_proc_net(path: &str, ipv6: bool) -> Option<SockTable> {
        let mut buf = String::new();
        fs::File::open(path).ok()?.read_to_string(&mut buf).ok()?;
        let mut map = SockTable::new();
        // Header is the first line; data starts on line 2.
        for line in buf.lines().skip(1) {
            // local_address is col 1, uid col 7, inode col 9 for the
            // tcp/udp tables.
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let local = cols[1];
            let Some((addr_hex, port_hex)) = local.split_once(':') else {
                continue;
            };
            let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            let Some(addr) = (if ipv6 {
                parse_hex_ipv6(addr_hex)
            } else {
                parse_hex_ipv4(addr_hex)
            }) else {
                continue;
            };
            let (Ok(uid), Ok(inode)) = (cols[7].parse::<u32>(), cols[9].parse::<u64>()) else {
                continue;
            };
            map.entry(port).or_default().push((addr, inode, uid));
        }
        Some(map)
    }

    pub(crate) fn find_pid_by_inode_cached(inode: u64) -> Option<(u32, String, String)> {
        let cache = INODE_MAP.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some((at, cached)) = cache.lock().get(&inode) {
            if at.elapsed() <= INODE_TTL {
                return cached.clone();
            }
        }
        // Walk outside the lock: a concurrent miss may duplicate one scan,
        // which beats serializing every lookup behind the /proc/*/fd
        // traversal (the expensive half the cache exists to amortize).
        let found = find_pid_by_inode(inode);
        let mut guard = cache.lock();
        if guard.len() >= INODE_CACHE_CAP {
            guard.clear();
        }
        guard.insert(inode, (Instant::now(), found.clone()));
        found
    }

    fn parse_hex_ipv4(s: &str) -> Option<IpAddr> {
        // /proc/net/tcp encodes the address as a little-endian 32-bit hex.
        // "0100007F" == 0x7F000001 == 127.0.0.1.
        if s.len() != 8 {
            return None;
        }
        let v = u32::from_str_radix(s, 16).ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(v.swap_bytes())))
    }

    fn parse_hex_ipv6(s: &str) -> Option<IpAddr> {
        if s.len() != 32 {
            return None;
        }
        // Eight 32-bit little-endian groups.
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let word_hex = &s[i * 8..(i + 1) * 8];
            let word = u32::from_str_radix(word_hex, 16).ok()?.swap_bytes();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    }

    fn addr_matches(found: IpAddr, target: IpAddr) -> bool {
        if found == target {
            return true;
        }
        // Kernel often reports the wildcard address (0.0.0.0 / ::) or the
        // IPv4-mapped form when the socket was opened on IPv6. Accept those.
        match (found, target) {
            (IpAddr::V4(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), IpAddr::V4(t)) => f.to_ipv4_mapped() == Some(t),
            _ => false,
        }
    }

    fn find_pid_by_inode(inode: u64) -> Option<(u32, String, String)> {
        let needle = format!("socket:[{inode}]");
        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let fd_dir: PathBuf = entry.path().join("fd");
            let Ok(rd) = fs::read_dir(&fd_dir) else {
                continue;
            };
            for fd in rd.flatten() {
                if let Ok(link) = fs::read_link(fd.path()) {
                    if link.to_string_lossy() == needle {
                        let exe_link = fs::read_link(entry.path().join("exe")).ok();
                        // `/proc/<pid>/comm` is truncated to TASK_COMM_LEN-1 = 15
                        // chars, which mangles long binary names (e.g. cargo test
                        // harnesses like `meow_tunnel-<16hex>`). Prefer the
                        // basename of `/proc/<pid>/exe` and fall back to comm only
                        // when exe is unreadable (kernel threads, perm denied).
                        let name = exe_link
                            .as_ref()
                            .and_then(|p| p.file_name())
                            .map(|s| s.to_string_lossy().into_owned())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| {
                                fs::read_to_string(entry.path().join("comm"))
                                    .unwrap_or_default()
                                    .trim()
                                    .to_string()
                            });
                        let exe = exe_link
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        return Some((pid, name, exe));
                    }
                }
            }
        }
        None
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Network, ProcessInfo, SocketAddr};
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
    use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
    use libproc::libproc::proc_pid::{listpidinfo, pidinfo, pidpath};
    use libproc::processes::{pids_by_type, ProcFilter};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tracing::trace;

    pub fn find_process(network: Network, local: SocketAddr) -> Option<ProcessInfo> {
        let pids = pids_by_type(ProcFilter::All).ok()?;
        for pid in pids {
            if pid == 0 {
                continue;
            }
            let pid = pid as i32;
            let Ok(info) = pidinfo::<BSDInfo>(pid, 0) else {
                continue;
            };
            let Some(fds) = pid_fds(pid, info.pbi_nfiles as usize) else {
                continue;
            };
            for fd in fds {
                if fd.proc_fdtype != ProcFDType::Socket as u32 {
                    continue;
                }
                let Ok(sfd) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) else {
                    continue;
                };
                let sinfo = sfd.psi.soi_proto;
                let kind = SocketInfoKind::from(sfd.psi.soi_kind);
                if !matches_socket(network, local, kind, &sinfo) {
                    continue;
                }
                trace!(pid, "process_lookup: matched socket via libproc");
                let name = pidpath(pid)
                    .ok()
                    .and_then(|p| p.rsplit('/').next().map(std::string::ToString::to_string))
                    .unwrap_or_default();
                let path = pidpath(pid).unwrap_or_default();
                let uid = unsafe {
                    let mut pinfo: libc::proc_bsdinfo = std::mem::zeroed();
                    let ret = libc::proc_pidinfo(
                        pid,
                        libc::PROC_PIDTBSDINFO,
                        0,
                        &mut pinfo as *mut _ as *mut libc::c_void,
                        std::mem::size_of::<libc::proc_bsdinfo>() as i32,
                    );
                    if ret as usize == std::mem::size_of::<libc::proc_bsdinfo>() {
                        Some(pinfo.pbi_uid)
                    } else {
                        None
                    }
                };
                return Some(ProcessInfo { name, path, uid });
            }
        }
        None
    }

    /// Upper bound on the fd-list buffer in [`pid_fds`] — 64 Ki entries is
    /// past any sane `RLIMIT_NOFILE`, and the buffer is a transient probe
    /// allocation (`ProcFDInfo` is 8 B; a doubling can overshoot the cap
    /// once, so ≤ ~1 MiB transient, reached only for a process that
    /// actually nears the bound).
    const PID_FD_CAP: usize = 1 << 16;

    /// Fetch a pid's fd table. `pbi_nfiles` is only a snapshot: a process
    /// that opened fds between the `PROC_PIDTBSDINFO` read and this call
    /// has more entries than it reports, and `PROC_PIDLISTFDS` silently
    /// truncates to the buffer size — the newest (highest-numbered) fds
    /// fall off first. A buffer that comes back exactly full may be
    /// hiding a tail, so retry with double capacity until the kernel
    /// reports headroom (or the bound is hit). This is what the
    /// dependent-crate test flake was: a parallel test opening sockets
    /// could push our own test process past the snapshot count, dropping
    /// the just-bound listener from the scan.
    pub(crate) fn pid_fds(
        pid: i32,
        reported_count: usize,
    ) -> Option<Vec<libproc::libproc::file_info::ProcFDInfo>> {
        let mut cap = reported_count.clamp(16, PID_FD_CAP);
        loop {
            match listpidinfo::<ListFDs>(pid, cap) {
                // Fewer entries than capacity: complete enumeration.
                Ok(fds) if fds.len() < cap => return Some(fds),
                // Exactly full: either the process holds precisely `cap`
                // fds (one wasted retry proves it) or the tail was cut.
                Ok(_) if cap < PID_FD_CAP => cap *= 2,
                Ok(fds) => return Some(fds),
                Err(_) => return None,
            }
        }
    }

    fn matches_socket(
        network: Network,
        local: SocketAddr,
        kind: SocketInfoKind,
        sinfo: &libproc::libproc::net_info::SocketInfoProto,
    ) -> bool {
        unsafe {
            match (network, kind) {
                (Network::Tcp, SocketInfoKind::Tcp) => {
                    let tcp = &sinfo.pri_tcp;
                    sock_matches(local, tcp.tcpsi_ini.insi_lport, &tcp.tcpsi_ini)
                }
                (Network::Udp, SocketInfoKind::In) => {
                    let ini = &sinfo.pri_in;
                    sock_matches(local, ini.insi_lport, ini)
                }
                _ => false,
            }
        }
    }

    fn sock_matches(
        target: SocketAddr,
        lport_net: i32,
        ini: &libproc::libproc::net_info::InSockInfo,
    ) -> bool {
        // `insi_lport` stores the port in network byte order in the low 16 bits.
        let port = (lport_net as u16).swap_bytes();
        if port != target.port() {
            return false;
        }
        // insi_vflag: 0x1 = IPv4, 0x2 = IPv6.
        let is_v6 = ini.insi_vflag & 0x2 != 0;
        let found_ip = unsafe {
            if is_v6 {
                IpAddr::V6(Ipv6Addr::from(ini.insi_laddr.ina_6.s6_addr))
            } else {
                let raw = ini.insi_laddr.ina_46.i46a_addr4.s_addr;
                IpAddr::V4(Ipv4Addr::from(u32::from_be(raw)))
            }
        };
        addr_matches(found_ip, target.ip())
    }

    fn addr_matches(found: IpAddr, target: IpAddr) -> bool {
        if found == target {
            return true;
        }
        match (found, target) {
            (IpAddr::V4(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), IpAddr::V4(t)) => f.to_ipv4_mapped() == Some(t),
            _ => false,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::{Network, ProcessInfo, SocketAddr};

    pub fn find_process(_network: Network, _local: SocketAddr) -> Option<ProcessInfo> {
        // Process lookup is not yet implemented for this platform. PROCESS-NAME,
        // PROCESS-PATH and UID rules will silently fail to match until it is.
        None
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{Network, ProcessInfo, SocketAddr};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tracing::trace;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const MAX_RETRIES: u32 = 3;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    pub fn find_process(network: Network, local: SocketAddr) -> Option<ProcessInfo> {
        let pid = match (network, local.is_ipv4()) {
            (Network::Tcp, true) => walk_tcp_table::<MIB_TCPROW_OWNER_PID>(AF_INET, local),
            (Network::Tcp, false) => walk_tcp_table::<MIB_TCP6ROW_OWNER_PID>(AF_INET6, local),
            (Network::Udp, true) => walk_udp_table::<MIB_UDPROW_OWNER_PID>(AF_INET, local),
            (Network::Udp, false) => walk_udp_table::<MIB_UDP6ROW_OWNER_PID>(AF_INET6, local),
        };
        let pid = pid?;
        let (name, path) = get_process_info(pid)?;
        trace!(pid, name, path, "process_lookup: matched via Win32 API");
        Some(ProcessInfo {
            name,
            path,
            uid: None,
        })
    }

    // ── Unified table walk ──────────────────────────────────────────────

    fn walk_tcp_table<R: RowAccess>(family: u32, target: SocketAddr) -> Option<u32> {
        for _ in 0..MAX_RETRIES {
            let mut buf_size: u32 = 0;
            unsafe {
                GetExtendedTcpTable(
                    std::ptr::null_mut(),
                    &mut buf_size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
            }
            let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
            let ret = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr() as *mut _,
                    &mut buf_size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if ret == 0 {
                return parse_table::<R>(&buf, target);
            }
            if ret != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }
        None
    }

    fn walk_udp_table<R: RowAccess>(family: u32, target: SocketAddr) -> Option<u32> {
        for _ in 0..MAX_RETRIES {
            let mut buf_size: u32 = 0;
            unsafe {
                GetExtendedUdpTable(
                    std::ptr::null_mut(),
                    &mut buf_size,
                    0,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                );
            }
            let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
            let ret = unsafe {
                GetExtendedUdpTable(
                    buf.as_mut_ptr() as *mut _,
                    &mut buf_size,
                    0,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            };
            if ret == 0 {
                return parse_table::<R>(&buf, target);
            }
            if ret != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }
        None
    }

    // ── Row access trait (unified for TCP and UDP) ───────────────────────

    trait RowAccess {
        fn local_addr(&self) -> IpAddr;
        fn local_port(&self) -> u16;
        fn owning_pid(&self) -> u32;
    }

    impl RowAccess for MIB_TCPROW_OWNER_PID {
        fn local_addr(&self) -> IpAddr {
            IpAddr::V4(Ipv4Addr::from(u32::from_be(self.dwLocalAddr)))
        }
        fn local_port(&self) -> u16 {
            u16::from_be(self.dwLocalPort as u16)
        }
        fn owning_pid(&self) -> u32 {
            self.dwOwningPid
        }
    }

    impl RowAccess for MIB_TCP6ROW_OWNER_PID {
        fn local_addr(&self) -> IpAddr {
            IpAddr::V6(Ipv6Addr::from(self.ucLocalAddr))
        }
        fn local_port(&self) -> u16 {
            u16::from_be(self.dwLocalPort as u16)
        }
        fn owning_pid(&self) -> u32 {
            self.dwOwningPid
        }
    }

    impl RowAccess for MIB_UDPROW_OWNER_PID {
        fn local_addr(&self) -> IpAddr {
            IpAddr::V4(Ipv4Addr::from(u32::from_be(self.dwLocalAddr)))
        }
        fn local_port(&self) -> u16 {
            u16::from_be(self.dwLocalPort as u16)
        }
        fn owning_pid(&self) -> u32 {
            self.dwOwningPid
        }
    }

    impl RowAccess for MIB_UDP6ROW_OWNER_PID {
        fn local_addr(&self) -> IpAddr {
            IpAddr::V6(Ipv6Addr::from(self.ucLocalAddr))
        }
        fn local_port(&self) -> u16 {
            u16::from_be(self.dwLocalPort as u16)
        }
        fn owning_pid(&self) -> u32 {
            self.dwOwningPid
        }
    }

    fn parse_table<R: RowAccess>(buf: &[u8], target: SocketAddr) -> Option<u32> {
        if buf.len() < 4 {
            return None;
        }
        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let row_size = std::mem::size_of::<R>();
        for i in 0..num_entries as usize {
            let offset = 4 + i * row_size;
            if offset + row_size > buf.len() {
                break;
            }
            // SAFETY: read_unaligned handles misalignment from Vec<u8>.
            let row = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const R) };
            if row.local_port() != target.port() {
                continue;
            }
            let addr = row.local_addr();
            if addr_matches(addr, target.ip()) {
                return Some(row.owning_pid());
            }
        }
        None
    }

    // ── Address matching ────────────────────────────────────────────────

    /// Match a row address against the target: exact match, wildcard
    /// (unspecified 0.0.0.0 / ::), or v4-mapped-v6.
    fn addr_matches(found: IpAddr, target: IpAddr) -> bool {
        if found == target {
            return true;
        }
        match (found, target) {
            (IpAddr::V4(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), IpAddr::V4(t)) => f.to_ipv4_mapped() == Some(t),
            _ => false,
        }
    }

    // ── Process path lookup ─────────────────────────────────────────────

    /// Use `QueryFullProcessImageNameW` with `PROCESS_QUERY_LIMITED_INFORMATION`.
    /// Per MSDN, this API is *documented* to work with a limited handle
    /// (unlike `GetModuleFileNameExW` which requires `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`).
    fn get_process_info(pid: u32) -> Option<(String, String)> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }

            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;
            let ok =
                QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut size);

            let _ = CloseHandle(handle);

            if ok == 0 {
                return None;
            }

            let path_str = String::from_utf16_lossy(&buf[..size as usize]);
            let name = std::path::Path::new(&path_str)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            Some((name, path_str))
        }
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod tests {
    use super::*;

    /// Regression for the dependent-crate full-run flake (seen on macOS in
    /// `meow-tunnel`'s process-enrichment tests): `pbi_nfiles` is a
    /// snapshot, `PROC_PIDLISTFDS` truncates to the buffer — under parallel
    /// fd churn the just-bound socket's entry fell off the tail and the
    /// lookup missed it. `pid_fds` must grow past a stale count.
    #[cfg(target_os = "macos")]
    #[test]
    fn pid_fds_grows_past_stale_snapshot_count() {
        use std::os::fd::AsRawFd;
        // Hold enough fds that the floor-clamped initial buffer (16)
        // provably cannot fit the table — `len() > 16` then demonstrates
        // the doubling retry actually ran, not merely the clamp floor.
        let _held: Vec<std::net::TcpListener> = (0..24)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let marker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let marker_fd = marker.as_raw_fd();
        let fds = platform::pid_fds(std::process::id() as i32, 1).expect("own pid must list fds");
        assert!(
            fds.len() > 16,
            "stale count must grow past the initial cap: {} entries",
            fds.len()
        );
        assert!(
            fds.iter().any(|f| f.proc_fd == marker_fd),
            "the just-bound socket fd must appear"
        );
    }

    #[test]
    fn finds_self_via_tcp_listener() {
        // Bind a TCP listener on 127.0.0.1:<ephemeral> and then ask
        // `find_process` who owns that endpoint — it must be this test binary.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let info = find_process(Network::Tcp, addr)
            .expect("process lookup should locate the current test process");
        // Win32 process lookup does not populate uid.
        #[cfg(not(target_os = "windows"))]
        assert!(info.uid.is_some(), "uid should be populated");
        // Exact-match guard-rail: the returned name must equal the full test
        // binary filename. On Linux this catches `/proc/<pid>/comm` truncation
        // (TASK_COMM_LEN=16 → 15-char cap) which mangles `<crate>-<16hex>`
        // cargo-test harness names — the bug fixed by 65f19e5.
        let expected = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .expect("current_exe should be readable in tests");
        assert_eq!(info.name, expected, "process name must not be truncated");
    }

    #[test]
    fn finds_self_via_udp_socket() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let info = find_process(Network::Udp, addr)
            .expect("process lookup should locate the current test process for UDP");
        assert!(!info.name.is_empty());
    }

    #[test]
    fn tcp_ipv6_lookup() {
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let info =
            find_process(Network::Tcp, addr).expect("TCP IPv6 process lookup should succeed");
        assert!(!info.name.is_empty());
    }

    #[test]
    fn udp_ipv6_lookup() {
        let sock = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let info =
            find_process(Network::Udp, addr).expect("UDP IPv6 process lookup should succeed");
        assert!(!info.name.is_empty());
    }

    #[test]
    fn udp_wildcard_binds_match() {
        // UDP sockets typically bind 0.0.0.0:port. A lookup targeting
        // 127.0.0.1:<same_port> should still match via the wildcard rule.
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let actual = sock.local_addr().unwrap();
        // Query with 127.0.0.1 instead of 0.0.0.0 — the row address is
        // unspecified, so the wildcard match path is exercised.
        let target = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            actual.port(),
        );
        let info = find_process(Network::Udp, target)
            .expect("UDP wildcard bind lookup should match via unspecified-address path");
        assert!(!info.name.is_empty());
    }

    #[test]
    fn unknown_endpoint_returns_none() {
        // Port 1 is reserved and should not be bound by any test-run process.
        let fake = "127.0.0.1:1".parse().unwrap();
        assert!(find_process(Network::Tcp, fake).is_none());
    }

    /// The blocking-pool wrapper must return exactly what the synchronous
    /// scan returns for the same endpoint (issue #515).
    #[tokio::test]
    async fn find_process_async_parity() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sync = find_process(Network::Tcp, addr);
        let async_result = find_process_async(Network::Tcp, addr).await;
        assert_eq!(sync.is_some(), async_result.is_some());
        if let (Some(s), Some(a)) = (sync, async_result) {
            assert_eq!(s.name, a.name);
            assert_eq!(s.path, a.path);
            assert_eq!(s.uid, a.uid);
        }
    }

    /// The Linux cache layer itself (issue #515). `sock_table`'s slots are
    /// shared process-wide, so fixture coverage goes through the pure
    /// parser rather than the cache — populating a slot with fixture data
    /// would poison parallel tests for `TABLE_TTL`.
    #[cfg(target_os = "linux")]
    mod linux_cache {
        use super::super::platform;
        use std::io::Write;

        #[test]
        fn parse_proc_net_reads_fixture() {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            // Header line + one row: 127.0.0.1:8080 (0100007F:1F90), uid 0,
            // inode 4242.
            writeln!(
                f,
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when \
                 retrnsmt   uid  timeout inode"
            )
            .unwrap();
            writeln!(
                f,
                "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 \
                 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0"
            )
            .unwrap();
            let table = platform::parse_proc_net(f.path().to_str().unwrap(), false)
                .expect("fixture must parse");
            let rows = table.get(&8080).expect("port 8080 row");
            assert_eq!(rows[0].0, "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
            assert_eq!(rows[0].1, 4242, "inode");
            assert_eq!(rows[0].2, 0, "uid");

            // An unreadable path yields None → cached as a lookup miss.
            assert!(platform::parse_proc_net("/nonexistent", false).is_none());
        }

        #[test]
        fn inode_cache_returns_none_for_unknown() {
            // u64::MAX never matches a real inode; the miss is cached.
            assert!(platform::find_pid_by_inode_cached(u64::MAX).is_none());
        }
    }
}

#[cfg(test)]
mod inbound_tests {
    use super::*;

    // The only test that sets the flag: it is process-global and one-way,
    // and the dead-off-platform assertions in meow-rules / meow-tunnel run
    // in other binaries.
    #[test]
    fn inbound_process_info_keeps_process_and_uid_rules_live() {
        enable_inbound_process_info();
        assert!(process_info_available());
        assert!(uid_info_available());
    }
}
