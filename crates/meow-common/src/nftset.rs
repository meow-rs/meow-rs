//! `dns.nftset`: add the address answers of domains the rules
//! send through the core to nftables sets, dnsmasq `nftset=` style, so a
//! firewall can intercept only those destinations and let everything else
//! take the kernel's forwarding path (flowtable / hardware offload).
//!
//! This module holds the spec (`family#table#set`) and the netlink writer;
//! the rule verdict lives in meow-tunnel and the answer hook in meow-dns.

use std::net::IpAddr;
use std::time::Duration;

/// Default element timeout: at least a day, like the DNS sets of dnsmasq-based router setups, so an
/// answer a downstream cache keeps serving stays covered.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(86_400);

/// `NFPROTO_*` values for the families a `family#table#set` spec accepts.
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_NETDEV: u8 = 5;
const NFPROTO_BRIDGE: u8 = 7;
const NFPROTO_IPV6: u8 = 10;

/// One nftables set: `family#table#set`, e.g. `inet#fw4#meow_proxy4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetRef {
    /// `NFPROTO_*` value of the table family.
    pub family: u8,
    pub table: String,
    pub set: String,
}

impl SetRef {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut it = spec.split('#');
        let (Some(family), Some(table), Some(set), None) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            return Err(format!("nftset `{spec}`: expected family#table#set"));
        };
        let family = match family {
            "inet" => NFPROTO_INET,
            "ip" => NFPROTO_IPV4,
            "ip6" => NFPROTO_IPV6,
            "bridge" => NFPROTO_BRIDGE,
            "netdev" => NFPROTO_NETDEV,
            other => return Err(format!("nftset `{spec}`: unknown family `{other}`")),
        };
        let valid = |s: &str| !s.is_empty() && s.len() < 256 && !s.contains('\0');
        if !valid(table) || !valid(set) {
            return Err(format!(
                "nftset `{spec}`: empty or oversized table/set name"
            ));
        }
        Ok(Self {
            family,
            table: table.to_owned(),
            set: set.to_owned(),
        })
    }
}

/// The parsed `dns.nftset` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftsetConfig {
    pub ipv4: Option<SetRef>,
    pub ipv6: Option<SetRef>,
    /// Minimum element timeout; an answer with a longer TTL gets its TTL.
    pub timeout: Duration,
}

impl NftsetConfig {
    /// `None` when neither family names a set.
    pub fn parse(
        ipv4: Option<&str>,
        ipv6: Option<&str>,
        timeout_secs: Option<u64>,
    ) -> Result<Option<Self>, String> {
        let ipv4 = ipv4.map(SetRef::parse).transpose()?;
        let ipv6 = ipv6.map(SetRef::parse).transpose()?;
        if ipv4.is_none() && ipv6.is_none() {
            return Ok(None);
        }
        // The slot names the address family the answers will carry: a set
        // that can't hold it dead-ends every add, so it is a spec error.
        // `inet` covers both families.
        if let Some(s) = &ipv4 {
            if !matches!(s.family, NFPROTO_INET | NFPROTO_IPV4) {
                return Err(format!(
                    "nftset ipv4 `{}#{}`: family must be `ip` or `inet`",
                    s.table, s.set
                ));
            }
        }
        if let Some(s) = &ipv6 {
            if !matches!(s.family, NFPROTO_INET | NFPROTO_IPV6) {
                return Err(format!(
                    "nftset ipv6 `{}#{}`: family must be `ip6` or `inet`",
                    s.table, s.set
                ));
            }
        }
        // Same Instant+Duration overflow class as `udp-timeout`
        // (issue #648): element-expiry arithmetic must never reach
        // panic=abort.
        let timeout = match timeout_secs {
            Some(s) if s > crate::MAX_DURATION_SECS => {
                return Err(format!(
                    "nftset timeout: {s}s exceeds the {}s ceiling",
                    crate::MAX_DURATION_SECS
                ));
            }
            Some(s) => Duration::from_secs(s),
            None => DEFAULT_TIMEOUT,
        };
        Ok(Some(Self {
            ipv4,
            ipv6,
            timeout,
        }))
    }

    pub fn set_for(&self, ip: IpAddr) -> Option<&SetRef> {
        match ip {
            IpAddr::V4(_) => self.ipv4.as_ref(),
            IpAddr::V6(_) => self.ipv6.as_ref(),
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::NftWriter;

#[cfg(target_os = "linux")]
mod linux {
    use super::SetRef;
    use std::io;
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;

    const NETLINK_NETFILTER: libc::c_int = 12;
    const NFNL_SUBSYS_NFTABLES: u16 = 10;
    const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
    const NFNL_MSG_BATCH_END: u16 = 0x11;
    const NFT_MSG_NEWSETELEM: u16 = 12;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_ACK: u16 = 0x4;
    const NLM_F_CREATE: u16 = 0x400;
    const NLMSG_ERROR: u16 = 2;
    const NLA_F_NESTED: u16 = 0x8000;
    const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
    const NFTA_SET_ELEM_LIST_SET: u16 = 2;
    const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
    const NFTA_LIST_ELEM: u16 = 1;
    const NFTA_SET_ELEM_KEY: u16 = 1;
    const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
    const NFTA_DATA_VALUE: u16 = 1;

    /// A netfilter netlink socket that adds set elements, one acked batch
    /// per element: the caller learns the element is in before it answers.
    pub struct NftWriter {
        fd: OwnedFd,
        seq: u32,
        buf: Vec<u8>,
    }

    impl NftWriter {
        pub fn new() -> io::Result<Self> {
            // SAFETY: plain socket(2); the fd is owned right away.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    NETLINK_NETFILTER,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is a fresh, valid descriptor nobody else owns.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let tv = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            // SAFETY: valid fd, option value points at a live timeval.
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    std::ptr::from_ref(&tv).cast(),
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            Ok(Self {
                fd,
                seq: 0,
                buf: Vec::with_capacity(256),
            })
        }

        /// Add `ip` to `set`; `timeout: None` for a set without `flags
        /// timeout`. Re-adding an element refreshes its timeout (Linux 6.x).
        pub fn add(
            &mut self,
            set: &SetRef,
            ip: IpAddr,
            timeout: Option<Duration>,
        ) -> io::Result<()> {
            self.seq = self.seq.wrapping_add(3);
            let seq = self.seq;
            let b = &mut self.buf;
            b.clear();
            put_msg(
                b,
                NFNL_MSG_BATCH_BEGIN,
                NLM_F_REQUEST,
                seq,
                0,
                NFNL_SUBSYS_NFTABLES,
                |_| {},
            );
            put_msg(
                b,
                (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM,
                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
                seq + 1,
                set.family,
                0,
                |b| {
                    put_attr(b, NFTA_SET_ELEM_LIST_TABLE, &cstr(&set.table));
                    put_attr(b, NFTA_SET_ELEM_LIST_SET, &cstr(&set.set));
                    nested(b, NFTA_SET_ELEM_LIST_ELEMENTS, |b| {
                        nested(b, NFTA_LIST_ELEM, |b| {
                            nested(b, NFTA_SET_ELEM_KEY, |b| match ip {
                                IpAddr::V4(a) => put_attr(b, NFTA_DATA_VALUE, &a.octets()),
                                IpAddr::V6(a) => put_attr(b, NFTA_DATA_VALUE, &a.octets()),
                            });
                            if let Some(t) = timeout {
                                let ms = u64::try_from(t.as_millis()).unwrap_or(u64::MAX);
                                put_attr(b, NFTA_SET_ELEM_TIMEOUT, &ms.to_be_bytes());
                            }
                        });
                    });
                },
            );
            put_msg(
                b,
                NFNL_MSG_BATCH_END,
                NLM_F_REQUEST,
                seq + 2,
                0,
                NFNL_SUBSYS_NFTABLES,
                |_| {},
            );

            // SAFETY: zeroed sockaddr_nl is the kernel address (pid 0).
            let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: valid fd, buffer and address of the stated lengths.
            let n = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    b.as_ptr().cast(),
                    b.len(),
                    0,
                    std::ptr::from_ref(&kernel).cast(),
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            self.read_ack(seq + 1)
        }

        /// Wait for the NLMSG_ERROR acking message `seq` (0 = success).
        fn read_ack(&mut self, seq: u32) -> io::Result<()> {
            let mut rx = [0u8; 4096];
            loop {
                // SAFETY: valid fd and buffer.
                let n =
                    unsafe { libc::recv(self.fd.as_raw_fd(), rx.as_mut_ptr().cast(), rx.len(), 0) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                #[allow(clippy::cast_sign_loss, reason = "checked non-negative above")]
                let mut p = &rx[..n as usize];
                while p.len() >= 16 {
                    let len = u32::from_ne_bytes(p[0..4].try_into().unwrap_or_default()) as usize;
                    let ty = u16::from_ne_bytes([p[4], p[5]]);
                    let mseq = u32::from_ne_bytes(p[8..12].try_into().unwrap_or_default());
                    if len < 16 || len > p.len() {
                        break;
                    }
                    if ty == NLMSG_ERROR && p.len() >= 20 {
                        let err = i32::from_ne_bytes(p[16..20].try_into().unwrap_or_default());
                        if err != 0 {
                            return Err(io::Error::from_raw_os_error(-err));
                        }
                        if mseq == seq {
                            return Ok(());
                        }
                    }
                    p = &p[align(len).min(p.len())..];
                }
            }
        }
    }

    fn align(n: usize) -> usize {
        (n + 3) & !3
    }

    fn cstr(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "netlink messages here are < 1 KiB"
    )]
    fn put_msg(
        b: &mut Vec<u8>,
        ty: u16,
        flags: u16,
        seq: u32,
        family: u8,
        res_id: u16,
        body: impl FnOnce(&mut Vec<u8>),
    ) {
        let start = b.len();
        b.extend_from_slice(&[0; 4]); // len
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(&flags.to_ne_bytes());
        b.extend_from_slice(&seq.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes()); // pid
        b.push(family); // nfgenmsg
        b.push(0); // NFNETLINK_V0
        b.extend_from_slice(&res_id.to_be_bytes());
        body(b);
        let len = (b.len() - start) as u32;
        b[start..start + 4].copy_from_slice(&len.to_ne_bytes());
        b.resize(start + align(len as usize), 0);
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "attributes here are < 1 KiB"
    )]
    fn put_attr(b: &mut Vec<u8>, ty: u16, data: &[u8]) {
        let len = 4 + data.len();
        b.extend_from_slice(&(len as u16).to_ne_bytes());
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(data);
        b.resize(b.len() + align(len) - len, 0);
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "attributes here are < 1 KiB"
    )]
    fn nested(b: &mut Vec<u8>, ty: u16, body: impl FnOnce(&mut Vec<u8>)) {
        let start = b.len();
        b.extend_from_slice(&[0; 2]);
        b.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        body(b);
        let len = (b.len() - start) as u16;
        b[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parses_like_dnsmasq_minus_the_family_digit() {
        let s = SetRef::parse("inet#fw4#meow4").unwrap();
        assert_eq!(
            (s.family, s.table.as_str(), s.set.as_str()),
            (1, "fw4", "meow4")
        );
        assert_eq!(SetRef::parse("ip6#t#s").unwrap().family, 10);
        assert!(SetRef::parse("inet#fw4").is_err());
        assert!(SetRef::parse("4#inet#fw4#s").is_err());
        assert!(SetRef::parse("arp#t#s").is_err());
        assert_eq!(NftsetConfig::parse(None, None, Some(5)).unwrap(), None);
        let c = NftsetConfig::parse(Some("ip#t#s"), None, None)
            .unwrap()
            .unwrap();
        assert_eq!(c.timeout, DEFAULT_TIMEOUT);
        assert!(c.set_for("::1".parse().unwrap()).is_none());
    }

    #[test]
    fn slots_reject_the_wrong_family_and_huge_timeouts() {
        assert!(NftsetConfig::parse(Some("ip6#t#s"), None, None).is_err());
        assert!(NftsetConfig::parse(None, Some("ip#t#s"), None).is_err());
        assert!(NftsetConfig::parse(Some("inet#t#s"), Some("inet#t#s"), None).is_ok());
        assert!(
            NftsetConfig::parse(Some("ip#t#s"), None, Some(crate::MAX_DURATION_SECS + 1)).is_err()
        );
        assert!(NftsetConfig::parse(Some("ip#t#s"), None, Some(crate::MAX_DURATION_SECS)).is_ok());
    }
}
