//! Batched datagram I/O for the WireGuard endpoint socket.
//!
//! [`BatchEndpoint`] wraps the `tokio::net::UdpSocket` both WireGuard
//! actors open toward their peers with batch calls that collapse a
//! wire burst into a single `recvmmsg`/`sendmmsg` syscall on Linux,
//! or a single `recvmsg_x`/`sendmsg_x` call on macOS — Darwin's
//! private-but-libSystem-exported batch SPI (see the `msgx` module).
//! Everywhere else the same calls degrade to a per-datagram `try_*`
//! loop — Android (a separate `target_os`) among them: `libc` binds
//! bionic's `sendmmsg`/`recvmmsg` as of 0.2.191, so the `linux`-only
//! cfg is a deliberate conservative choice, not a missing binding —
//! so the calling actors keep one code path and the syscall savings
//! are strictly an optimization. On macOS the `no-macos-sendmsg-x`
//! feature compiles the fallback back in: an opt-out for
//! environments that audit or shim private SPI (enable it via
//! `-p meow-wgstack --features no-macos-sendmsg-x`, or
//! `meow-wgstack/no-macos-sendmsg-x` from a direct dependent —
//! meow-proxy/meow-listener; the release bundles do not re-export
//! it). The ordinary `try_*`/`recv*` methods are forwarded for the
//! single-datagram paths that remain.
//!
//! Batch semantics match the per-packet loops they replace: a short
//! count means the next datagram is the boundary the kernel stopped
//! at — `sendmmsg` and `sendmsg_x` alike fold a post-partial error
//! into the returned count, so re-issuing that datagram with
//! `try_send`/`try_send_to` is how the caller learns `WouldBlock`
//! (requeue) from a real errno (log and drop, then continue). The
//! batched calls go straight to the raw fd — they never consult
//! tokio's cached readiness, so a cold (never-polled) socket still
//! reaches the kernel; see [`BatchEndpoint::BATCHED_SYSCALLS`].

use std::io;
use std::net::SocketAddr;

/// The stack arrays behind one batch call are sized to the wire drain
/// bound, so a single `sendmmsg`/`recvmmsg` covers a whole staged
/// batch. `pkts`/`bufs` longer than this are chunked (or clamped for
/// receive) inside the call.
use crate::WIRE_DRAIN_BUDGET;

/// A `tokio::net::UdpSocket` plus batch-syscall wrappers. `connected`
/// records whether the socket has a bound peer: on one, sends carry
/// no per-datagram destination (kernel `send()` semantics); on an
/// unconnected one each datagram needs its own address.
pub struct BatchEndpoint {
    inner: tokio::net::UdpSocket,
    connected: bool,
}

impl BatchEndpoint {
    /// `true` when [`send_batch`](Self::send_batch)/
    /// [`send_batch_to`](Self::send_batch_to)/
    /// [`recv_batch`](Self::recv_batch) issue real batched syscalls —
    /// `sendmmsg`/`recvmmsg` on Linux, `sendmsg_x`/`recvmsg_x` on
    /// macOS — rather than the per-datagram `try_*` fallback loop.
    /// The batched calls go straight to the raw fd: they never consult
    /// tokio's cached readiness, so a batch on a cold (never-polled)
    /// socket still reaches the kernel — the behaviour the downstream
    /// requeue pins key on.
    pub const BATCHED_SYSCALLS: bool = cfg!(any(
        target_os = "linux",
        all(target_os = "macos", not(feature = "no-macos-sendmsg-x"))
    ));

    /// Wrap a socket bound to one peer (the outbound pump's endpoint).
    pub fn connected(inner: tokio::net::UdpSocket) -> Self {
        Self {
            inner,
            connected: true,
        }
    }

    /// Wrap an unconnected socket (the inbound listener's endpoint):
    /// datagrams carry their destination per call.
    pub fn unconnected(inner: tokio::net::UdpSocket) -> Self {
        Self {
            inner,
            connected: false,
        }
    }

    // ── single-datagram passthroughs ─────────────────────────────

    /// Nonblocking single-datagram receive (connected peer).
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.try_recv(buf)
    }

    /// Nonblocking single-datagram receive, reporting the source.
    pub fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.try_recv_from(buf)
    }

    /// Nonblocking single-datagram send on a connected socket.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.try_send(buf)
    }

    /// Nonblocking single-datagram send to `addr`.
    pub fn try_send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.try_send_to(buf, addr)
    }

    /// Async single-datagram receive (connected peer) — the pump's
    /// `select!` driver.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf).await
    }

    /// Async single-datagram receive with source — the listener's
    /// `select!` driver.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    /// The socket's local address (the listener's bound-port lookup).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Reactor readiness passthroughs the tests await before batch
    /// calls: every `try_*` gates on the reactor's *cached* readiness,
    /// so a just-registered socket reads `WouldBlock` until the driver
    /// has polled it once. Long-lived actors never see that window —
    /// their select arms poll the socket before any `try_*` runs.
    #[cfg(test)]
    pub async fn readable(&self) -> io::Result<()> {
        self.inner.readable().await
    }

    /// See [`readable`](Self::readable).
    #[cfg(test)]
    pub async fn writable(&self) -> io::Result<()> {
        self.inner.writable().await
    }

    // ── batch calls ──────────────────────────────────────────────

    /// Drain up to `min(bufs.len(), budget, WIRE_DRAIN_BUDGET)`
    /// datagrams — one `recvmmsg` on Linux, one `recvmsg_x` on macOS,
    /// a `try_recv_buf` loop elsewhere. The third clamp is the
    /// stack-array bound: a single batched call can never service more
    /// slots than its arrays hold, and the fallback loop inherits the
    /// same bound so both paths agree on what one call is allowed to
    /// do. Every
    /// slot's whole *capacity* is its receive window — never its
    /// current length — so a persistent slot set serves batch after
    /// batch without restaging. On return, each of `bufs[..ret]` is
    /// sized to its datagram; the contents of later slots are
    /// unspecified. This is a connected-peer read: sources are not
    /// reported because the pump's socket only ever receives from the
    /// bound peer.
    pub fn recv_batch(&self, bufs: &mut [Vec<u8>], budget: usize) -> usize {
        let n = bufs.len().min(budget).min(WIRE_DRAIN_BUDGET);
        #[cfg(target_os = "linux")]
        {
            self.recv_batch_mmsg(&mut bufs[..n])
        }
        #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
        {
            self.recv_batch_msgx(&mut bufs[..n])
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", not(feature = "no-macos-sendmsg-x"))
        )))]
        {
            let mut got = 0;
            for buf in &mut bufs[..n] {
                // `try_recv_buf` appends into spare capacity; clearing
                // first makes the whole capacity the window.
                buf.clear();
                match self.inner.try_recv_buf(buf) {
                    Ok(_) => got += 1,
                    Err(e) => {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            tracing::debug!("wireguard endpoint recv_batch error: {e}");
                        }
                        break;
                    }
                }
            }
            got
        }
    }

    /// Send every datagram to `addr` — `send()` semantics on a
    /// connected endpoint (the `mmsghdr`s carry no name), `sendto` on
    /// an unconnected one. Returns the leading count the kernel
    /// accepted; a short count means the datagram at that index
    /// stopped the batch — replay it for the errno (see the module
    /// docs).
    pub fn send_batch(&self, pkts: &[&[u8]], addr: SocketAddr) -> usize {
        self.send_batch_inner(pkts, |buf| (addr, *buf))
    }

    /// The per-destination shape of [`send_batch`](Self::send_batch) —
    /// `pkts[i].0` is that datagram's target on an unconnected
    /// endpoint (the listener's outbox). On a connected endpoint the
    /// addresses are advisory only: the kernel already sends to the
    /// bound peer.
    pub fn send_batch_to(&self, pkts: &[(SocketAddr, &[u8])]) -> usize {
        self.send_batch_inner(pkts, |(a, b)| (*a, *b))
    }

    /// Batched-syscall platforms (`sendmmsg`/`sendmsg_x` below).
    /// Elsewhere: a `try_send`/`try_send_to` loop that stops at the
    /// first error — the same short-count contract either way.
    #[cfg(not(any(
        target_os = "linux",
        all(target_os = "macos", not(feature = "no-macos-sendmsg-x"))
    )))]
    fn send_batch_inner<T>(&self, pkts: &[T], get: impl Fn(&T) -> (SocketAddr, &[u8])) -> usize {
        let mut sent = 0;
        for t in pkts {
            let (addr, buf) = get(t);
            let r = if self.connected {
                self.inner.try_send(buf)
            } else {
                self.inner.try_send_to(buf, addr)
            };
            match r {
                Ok(_) => sent += 1,
                Err(_) => break,
            }
        }
        sent
    }

    /// One or more `sendmmsg` calls over ≤[`WIRE_DRAIN_BUDGET`]-sized
    /// stack arrays, looping until the batch is gone or a datagram
    /// errors — the kernel reports a partial batch as the sent count,
    /// so the failing datagram always sits at the returned index.
    #[cfg(target_os = "linux")]
    fn send_batch_inner<T>(&self, pkts: &[T], get: impl Fn(&T) -> (SocketAddr, &[u8])) -> usize {
        use std::os::fd::AsRawFd;
        let mut sent = 0usize;
        while sent < pkts.len() {
            let n = (pkts.len() - sent).min(WIRE_DRAIN_BUDGET);
            // SAFETY: `iovec`, `mmsghdr` and `sockaddr_storage` are C
            // PODs — the all-zero bit pattern is valid for every field
            // (null pointer, zero length, family AF_UNSPEC).
            let mut iov: [libc::iovec; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
            let mut sas: [libc::sockaddr_storage; WIRE_DRAIN_BUDGET] =
                unsafe { std::mem::zeroed() };
            for (j, t) in pkts[sent..sent + n].iter().enumerate() {
                let (addr, buf) = get(t);
                iov[j] = libc::iovec {
                    iov_base: buf.as_ptr().cast_mut().cast(),
                    iov_len: buf.len(),
                };
                msgs[j].msg_hdr.msg_iov = &mut iov[j];
                msgs[j].msg_hdr.msg_iovlen = 1;
                if !self.connected {
                    msgs[j].msg_hdr.msg_namelen = write_sockaddr(&mut sas[j], &addr);
                    msgs[j].msg_hdr.msg_name = (&mut sas[j]) as *mut _ as *mut _;
                }
            }
            // SAFETY: `fd` is a live nonblocking socket; `msgs`
            // describes `n` headers whose iovecs point at `pkts` data
            // that outlives this call (the kernel only reads through
            // send iovecs) and whose names point at `sas`.
            let ret = unsafe {
                libc::sendmmsg(
                    self.inner.as_raw_fd(),
                    msgs.as_mut_ptr(),
                    n as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                )
            };
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted && sent == 0 {
                    continue;
                }
                break;
            }
            sent += ret as usize;
            if (ret as usize) < n {
                break;
            }
        }
        sent
    }

    /// One `recvmmsg` into the staged buffers; the kernel stops at the
    /// first empty/error, so a partial batch means the socket is dry.
    #[cfg(target_os = "linux")]
    fn recv_batch_mmsg(&self, bufs: &mut [Vec<u8>]) -> usize {
        use std::os::fd::AsRawFd;
        let n = bufs.len().min(WIRE_DRAIN_BUDGET);
        let bufs = &mut bufs[..n];
        if bufs.is_empty() {
            return 0;
        }
        // SAFETY: as in `send_batch_inner` — C POD arrays, all-zero
        // valid.
        let mut iov: [libc::iovec; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
        for (j, buf) in bufs.iter_mut().enumerate() {
            iov[j] = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.capacity(),
            };
            msgs[j].msg_hdr.msg_iov = &mut iov[j];
            msgs[j].msg_hdr.msg_iovlen = 1;
        }
        // SAFETY: `fd` is a live nonblocking socket; `msgs` describes
        // `bufs.len()` iovecs each covering that Vec's whole
        // allocation, initialised or not — writes through the raw
        // pointer are in-bounds and no Rust reference aliases them.
        let ret = unsafe {
            libc::recvmmsg(
                self.inner.as_raw_fd(),
                msgs.as_mut_ptr(),
                bufs.len() as libc::c_uint,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if ret <= 0 {
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::WouldBlock {
                    tracing::debug!("wireguard endpoint recvmmsg error: {e}");
                }
            }
            return 0;
        }
        let got = ret as usize;
        for (j, buf) in bufs[..got].iter_mut().enumerate() {
            let len = (msgs[j].msg_len as usize).min(buf.capacity());
            // SAFETY: the kernel wrote the first `msg_len` bytes of
            // `buf`'s allocation (msg_len ≤ the advertised capacity),
            // so those bytes are initialised and extending `len` over
            // them is sound.
            unsafe { buf.set_len(len) };
        }
        got
    }

    /// macOS: `sendmsg_x` over stack-built `msghdr_x`/`iovec` arrays —
    /// the same shape as the Linux `sendmmsg` path, chunked at
    /// [`WIRE_DRAIN_BUDGET`]. On a connected UDP socket XNU takes the
    /// `sendit_x`/`sosend_list` fast path (no per-datagram name); on an
    /// unconnected one each header's `msg_name` carries its
    /// destination and the kernel loops `sendit` — still one syscall
    /// per chunk, per-datagram addressing preserved.
    #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
    fn send_batch_inner<T>(&self, pkts: &[T], get: impl Fn(&T) -> (SocketAddr, &[u8])) -> usize {
        use std::os::fd::AsRawFd;
        let mut sent = 0usize;
        while sent < pkts.len() {
            let n = (pkts.len() - sent).min(WIRE_DRAIN_BUDGET);
            // SAFETY: `iovec`, `msghdr_x` and `sockaddr_storage` are C
            // PODs — the all-zero bit pattern is valid for every field
            // (null pointer, zero length, family AF_UNSPEC) and zeroed
            // `msg_flags`/`msg_datalen` are the input values
            // `sendmsg_x` requires.
            let mut iov: [libc::iovec; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
            let mut msgs: [msgx::msghdr_x; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
            let mut sas: [libc::sockaddr_storage; WIRE_DRAIN_BUDGET] =
                unsafe { std::mem::zeroed() };
            for (j, t) in pkts[sent..sent + n].iter().enumerate() {
                let (addr, buf) = get(t);
                iov[j] = libc::iovec {
                    iov_base: buf.as_ptr().cast_mut().cast(),
                    iov_len: buf.len(),
                };
                msgs[j].msg_iov = &mut iov[j];
                msgs[j].msg_iovlen = 1;
                if !self.connected {
                    msgs[j].msg_namelen = write_sockaddr(&mut sas[j], &addr);
                    msgs[j].msg_name = (&mut sas[j]) as *mut _ as *mut _;
                }
            }
            // SAFETY: `fd` is a live nonblocking socket; `msgs` holds
            // `n` headers whose iovecs point at `pkts` data that
            // outlives this call (the kernel only reads through send
            // iovecs) and whose names point at `sas`. `MSG_DONTWAIT`
            // is redundant with O_NONBLOCK but states the contract.
            let ret = unsafe {
                msgx::sendmsg_x(
                    self.inner.as_raw_fd(),
                    msgs.as_ptr(),
                    n as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted && sent == 0 {
                    continue;
                }
                break;
            }
            sent += ret as usize;
            if (ret as usize) < n {
                break;
            }
        }
        sent
    }

    /// One `recvmsg_x` into the staged buffers — XNU's batched
    /// `soreceive_m_list`, which stops when the socket queue runs dry
    /// under `MSG_DONTWAIT` and reports each datagram's received length
    /// in `msg_datalen` (bytes actually copied, ≤ the advertised iov
    /// capacity). `msgs[..got]` is the only span the kernel rewrote.
    #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
    fn recv_batch_msgx(&self, bufs: &mut [Vec<u8>]) -> usize {
        use std::os::fd::AsRawFd;
        let n = bufs.len().min(WIRE_DRAIN_BUDGET);
        let bufs = &mut bufs[..n];
        if bufs.is_empty() {
            return 0;
        }
        // SAFETY: as in `send_batch_inner` — C POD arrays, all-zero
        // valid; `recvmsg_x` requires zeroed `msg_flags` on input.
        let mut iov: [libc::iovec; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
        let mut msgs: [msgx::msghdr_x; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
        for (j, buf) in bufs.iter_mut().enumerate() {
            iov[j] = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.capacity(),
            };
            msgs[j].msg_iov = &mut iov[j];
            msgs[j].msg_iovlen = 1;
        }
        // SAFETY: `fd` is a live nonblocking socket; `msgs` describes
        // `n` iovecs each covering that Vec's whole allocation,
        // initialised or not — writes through the raw pointer are
        // in-bounds and no Rust reference aliases them.
        let ret = unsafe {
            msgx::recvmsg_x(
                self.inner.as_raw_fd(),
                msgs.as_mut_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if ret <= 0 {
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::WouldBlock {
                    tracing::debug!("wireguard endpoint recvmsg_x error: {e}");
                }
            }
            return 0;
        }
        let got = ret as usize;
        for (j, buf) in bufs[..got].iter_mut().enumerate() {
            let len = msgs[j].msg_datalen.min(buf.capacity());
            // SAFETY: the kernel wrote the first `msg_datalen` bytes
            // of `buf`'s allocation (datalen is the copied count, ≤
            // the advertised capacity), so those bytes are initialised
            // and extending `len` over them is sound.
            unsafe { buf.set_len(len) };
        }
        got
    }
}

/// Darwin's batched-datagram SPI: `sendmsg_x`/`recvmsg_x`, declared in
/// XNU's kernel-side `bsd/sys/socket_private.h` and exported by
/// libSystem — no `#[link]` attribute needed (libSystem is always in
/// the image). Private SPI but a stable presence since macOS 10.12,
/// used in production by mDNSResponder, Network.framework and
/// WireGuard's Apple clients; the `no-macos-sendmsg-x` feature is the
/// escape hatch should that ever change.
///
/// Call contract (from `bsd/kern/uipc_syscalls.c`, xnu-11417):
/// - `sendmsg_x` returns the count of datagrams sent; a mid-batch
///   failure folds into a short count exactly like `sendmmsg`
///   (`ERESTART`/`EINTR`/`EWOULDBLOCK`/`ENOBUFS`/`EMSGSIZE` after a
///   partial send return the count, not the errno). `msg_flags` and
///   `msg_datalen` must be zero on input. A connected datagram socket
///   takes the `sendit_x`/`sosend_list` fast path; an unconnected one
///   runs an in-kernel `sendit` loop that honours each message's
///   `msg_name`/`msg_namelen` — the header comment's "address … not
///   supported" is stale relative to the implementation.
/// - `recvmsg_x` returns the count of datagrams received (the first
///   message may block only without `MSG_DONTWAIT` — we always pass
///   it), writing each message's copied byte count into `msg_datalen`.
///   `cnt` must be in `1..=kern.ipc.maxrecvmsgx` (default 256).
#[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
mod msgx {
    /// The `msghdr_x` wire layout, verbatim from `socket_private.h`'s
    /// `struct msghdr_x` — a `msghdr` plus the trailing `msg_datalen`.
    /// Every macOS target is LP64: pointers and `size_t` are 8-byte,
    /// `socklen_t`/`int` 4-byte — 56 bytes, 8-aligned, matching the
    /// kernel's `struct user64_msghdr_x`. The C spelling is kept so
    /// this stays diffable against the header.
    #[repr(C)]
    #[allow(non_camel_case_types, reason = "keeps XNU's C spelling")]
    pub struct msghdr_x {
        pub msg_name: *mut libc::c_void,
        pub msg_namelen: libc::socklen_t,
        pub msg_iov: *mut libc::iovec,
        pub msg_iovlen: libc::c_int,
        pub msg_control: *mut libc::c_void,
        pub msg_controllen: libc::socklen_t,
        pub msg_flags: libc::c_int,
        pub msg_datalen: usize,
    }

    // Layout pin: the kernel copyin is `struct user64_msghdr_x` —
    // identical field order/sizes. If either assert trips the binding
    // drifted from the wire format.
    const _: () = assert!(size_of::<msghdr_x>() == 56);
    const _: () = assert!(align_of::<msghdr_x>() == 8);
    const _: () = assert!(std::mem::offset_of!(msghdr_x, msg_datalen) == 48);

    extern "C" {
        /// `ssize_t sendmsg_x(int, const struct msghdr_x *, u_int, int)`.
        pub fn sendmsg_x(
            socket: libc::c_int,
            msgp: *const msghdr_x,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> libc::ssize_t;

        /// `ssize_t recvmsg_x(int, const struct msghdr_x *, u_int, int)`
        /// — the header writes `const msgp` but the kernel's copyouts
        /// write `msg_datalen`/`msg_flags` back through the array, so
        /// the binding declares `*mut`.
        pub fn recvmsg_x(
            socket: libc::c_int,
            msgp: *mut msghdr_x,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> libc::ssize_t;
    }
}

/// Serialize `addr` into `storage`, returning the `msg_namelen` the
/// kernel expects for the family.
#[cfg(target_os = "linux")]
fn write_sockaddr(storage: &mut libc::sockaddr_storage, addr: &SocketAddr) -> libc::socklen_t {
    match addr {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `sockaddr_in` fits inside `sockaddr_storage`.
            unsafe {
                std::ptr::write(
                    (storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                    sa,
                );
            }
            size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: `sockaddr_in6` fits inside `sockaddr_storage`.
            unsafe {
                std::ptr::write(
                    (storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                    sa,
                );
            }
            size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Serialize `addr` into `storage`, returning the `msg_namelen` the
/// kernel expects for the family — the Darwin variant, whose
/// `sockaddr_in`/`sockaddr_in6` lead with the BSD `sin_len` byte the
/// kernel validates on `sendto`-style calls.
#[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
fn write_sockaddr(storage: &mut libc::sockaddr_storage, addr: &SocketAddr) -> libc::socklen_t {
    match addr {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_len: size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `sockaddr_in` fits inside `sockaddr_storage`.
            unsafe {
                std::ptr::write(
                    (storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                    sa,
                );
            }
            size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_len: size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: `sockaddr_in6` fits inside `sockaddr_storage`.
            unsafe {
                std::ptr::write(
                    (storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                    sa,
                );
            }
            size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

#[cfg(test)]
mod tests {
    //! Loopback UDP batch I/O. On Linux these drive the real
    //! `sendmmsg`/`recvmmsg` path, on macOS `sendmsg_x`/`recvmsg_x`
    //! (unless `no-macos-sendmsg-x` put the fallback back), elsewhere
    //! the per-datagram loop.
    use super::*;

    fn std_sock() -> std::net::UdpSocket {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        s.set_nonblocking(true).expect("nonblocking");
        s
    }

    fn ep(s: std::net::UdpSocket, connected: bool) -> BatchEndpoint {
        let t = tokio::net::UdpSocket::from_std(s).expect("tokio socket");
        if connected {
            BatchEndpoint::connected(t)
        } else {
            BatchEndpoint::unconnected(t)
        }
    }

    /// `send_batch_to` lands the whole batch at the receiver, in
    /// order; the receiving side sees exactly the staged datagrams.
    #[tokio::test(flavor = "current_thread")]
    async fn send_batch_to_order_and_count() {
        let a = ep(std_sock(), false);
        let b_sock = std_sock();
        let b_addr = b_sock.local_addr().expect("addr");
        let b = ep(b_sock, false);

        const N: usize = 10;
        let payloads: Vec<Vec<u8>> = (0..N).map(|i| vec![i as u8; 32 + i]).collect();
        let refs: Vec<(SocketAddr, &[u8])> =
            payloads.iter().map(|p| (b_addr, p.as_slice())).collect();
        a.writable().await.expect("sender writable");
        assert_eq!(a.send_batch_to(&refs), N);

        // `readable` resolves on the first datagram; the rest of the
        // batch can still be in flight, so drain with a deadline.
        let got = drain_all(&b, N).await;
        assert_eq!(got, payloads, "every datagram exactly once, in order");
    }

    /// A connected endpoint's `send_batch` delivers to the bound peer
    /// — the pump's shape — again with order and count preserved.
    #[tokio::test(flavor = "current_thread")]
    async fn send_batch_connected_peer() {
        let a_sock = std_sock();
        let b_sock = std_sock();
        let b_addr = b_sock.local_addr().expect("addr");
        a_sock.connect(b_addr).expect("connect");
        let a = ep(a_sock, true);
        let b = ep(b_sock, false);

        const N: usize = 8;
        let payloads: Vec<Vec<u8>> = (0..N).map(|i| vec![0xA0 + i as u8; 48]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        a.writable().await.expect("sender writable");
        assert_eq!(a.send_batch(&refs, b_addr), N);

        let got = drain_all(&b, N).await;
        assert_eq!(got, payloads, "every datagram exactly once, in order");
    }

    /// `recv_batch` fills leading slots, sizes each to its datagram,
    /// and leaves every slot's capacity intact for the next batch.
    /// `budget` clamps the drain below the slot count.
    #[tokio::test(flavor = "current_thread")]
    async fn recv_batch_fills_leading_slots() {
        let a_sock = std_sock();
        let a_addr = a_sock.local_addr().expect("addr");
        let b_sock = std_sock();
        b_sock.connect(a_addr).expect("connect");
        let b = ep(b_sock, true);

        const N: usize = 5;
        for i in 0..N {
            a_sock
                .send_to(&vec![i as u8; 40 + i], b.local_addr().expect("addr"))
                .expect("send");
        }

        let mut bufs: Vec<Vec<u8>> = (0..10).map(|_| vec![0u8; 128]).collect();
        // `readable` resolves on the first datagram; the rest of the
        // backlog can still be in flight, so top up across calls until
        // the queue yields all N. A 0-returning drain clears the
        // cached readiness on the fallback path, so re-arm between
        // calls; on the raw-syscall paths each call re-reads the
        // kernel queue regardless.
        b.readable().await.expect("readable");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut n = 0;
        while n < N {
            n += b.recv_batch(&mut bufs[n..], 10 - n);
            if n < N {
                match tokio::time::timeout_at(deadline, b.readable()).await {
                    Ok(r) => r.expect("readable"),
                    Err(_) => panic!("recv_batch stalled at {n}/{N} datagrams"),
                }
            }
        }
        for (i, buf) in bufs[..n].iter().enumerate() {
            assert_eq!(buf.len(), 40 + i);
            assert!(buf.iter().all(|&x| x == i as u8));
        }
        assert_eq!(
            bufs[n].capacity(),
            128,
            "slot capacity survives for the next batch"
        );

        // A smaller budget drains only the first `budget` datagrams.
        for i in 0..N {
            a_sock
                .send_to(&[i as u8; 20], b.local_addr().expect("addr"))
                .expect("send");
        }
        let mut bufs: Vec<Vec<u8>> = (0..10).map(|_| vec![0u8; 128]).collect();
        // The first drain ran the socket dry, clearing cached
        // readiness — re-arm it before the second batch, and top up
        // for the same in-flight reason as above. The per-call budget
        // keeps the total clamped at 3.
        b.readable().await.expect("readable");
        let mut n = 0;
        while n < 3 {
            n += b.recv_batch(&mut bufs[n..], 3 - n);
            if n < 3 {
                match tokio::time::timeout_at(deadline, b.readable()).await {
                    Ok(r) => r.expect("readable"),
                    Err(_) => panic!("recv_batch stalled at {n}/3 datagrams"),
                }
            }
        }
        assert_eq!(n, 3, "budget clamps the drain");
    }

    /// Read `expected` datagrams off `sock` in wire order, polling
    /// until the count is met or the deadline passes — loopback
    /// delivery is not synchronous with the sender's `send` (on Linux
    /// each datagram crosses a softirq backlog first).
    async fn drain_all(sock: &BatchEndpoint, expected: usize) -> Vec<Vec<u8>> {
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut buf = vec![0u8; 65536];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while got.len() < expected {
            match tokio::time::timeout_at(deadline, sock.readable()).await {
                Ok(r) => r.expect("readable"),
                Err(_) => break,
            }
            while let Ok(n) = sock.try_recv(&mut buf) {
                got.push(buf[..n].to_vec());
            }
        }
        got
    }

    /// Chunks past the [`WIRE_DRAIN_BUDGET`] stack-array bound: a
    /// 130-datagram `send_batch` takes three mmsg rounds on Linux —
    /// the `pkts[sent..sent + n]` offset must stay exact — and a plain
    /// loop elsewhere. The receiver sees every datagram once, in
    /// order.
    #[tokio::test(flavor = "current_thread")]
    async fn send_batch_chunks_past_stack_bound() {
        let a_sock = std_sock();
        let b_sock = std_sock();
        let b_addr = b_sock.local_addr().expect("addr");
        a_sock.connect(b_addr).expect("connect");
        let a = ep(a_sock, true);
        let b = ep(b_sock, false);

        const N: usize = 130; // > 2 × WIRE_DRAIN_BUDGET ⇒ ≥3 kernel rounds
        let payloads: Vec<Vec<u8>> = (0..N).map(|i| vec![i as u8; 8 + i]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        a.writable().await.expect("sender writable");
        assert_eq!(a.send_batch(&refs, b_addr), N, "all chunks sent");

        let got = drain_all(&b, N).await;
        assert_eq!(got, payloads, "every datagram exactly once, in order");
    }

    /// The unconnected half of the same pin: `send_batch_to` carries
    /// each datagram's own destination across the same chunk boundary.
    #[tokio::test(flavor = "current_thread")]
    async fn send_batch_to_chunks_past_stack_bound() {
        let a = ep(std_sock(), false);
        let b_sock = std_sock();
        let b_addr = b_sock.local_addr().expect("addr");
        let b = ep(b_sock, false);

        const N: usize = 130;
        let payloads: Vec<Vec<u8>> = (0..N).map(|i| vec![i as u8; 8 + i]).collect();
        let refs: Vec<(SocketAddr, &[u8])> =
            payloads.iter().map(|p| (b_addr, p.as_slice())).collect();
        a.writable().await.expect("sender writable");
        assert_eq!(a.send_batch_to(&refs), N, "all chunks sent");

        let got = drain_all(&b, N).await;
        assert_eq!(got, payloads, "every datagram exactly once, in order");
    }

    /// The third `recv_batch` clamp: a slot set wider than
    /// [`WIRE_DRAIN_BUDGET`] is serviced a stack-array-sized slice at
    /// a time — one call never exceeds the mmsg array bound, and the
    /// remainder surfaces on the next call.
    #[tokio::test(flavor = "current_thread")]
    async fn recv_batch_clamps_to_stack_bound() {
        let a_sock = std_sock();
        let a_addr = a_sock.local_addr().expect("addr");
        let b_sock = std_sock();
        b_sock.connect(a_addr).expect("connect");
        let b = ep(b_sock, true);

        const N: usize = WIRE_DRAIN_BUDGET + 6;
        for i in 0..N {
            a_sock
                .send_to(&[i as u8; 20], b.local_addr().expect("addr"))
                .expect("send");
        }

        let mut bufs: Vec<Vec<u8>> = (0..N).map(|_| vec![0u8; 128]).collect();
        b.readable().await.expect("readable");
        // `readable` resolves on the first datagram; give the backlog
        // a wide margin to land the rest so the queue provably holds
        // ≥64 before the batch is measured.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let first = b.recv_batch(&mut bufs, N);
        assert_eq!(
            first, WIRE_DRAIN_BUDGET,
            "one call never exceeds the stack-array bound"
        );
        for (i, buf) in bufs[..first].iter().enumerate() {
            assert_eq!(buf.as_slice(), &[i as u8; 20]);
        }

        b.readable().await.expect("readable");
        let second = b.recv_batch(&mut bufs, N);
        assert_eq!(second, N - WIRE_DRAIN_BUDGET);
        for (i, buf) in bufs[..second].iter().enumerate() {
            assert_eq!(buf.as_slice(), &[(i + first) as u8; 20]);
        }
    }

    /// P4-3 msgx pin — on macOS `send_batch`/`recv_batch` must be the
    /// real `sendmsg_x`/`recvmsg_x` syscalls, not the per-datagram
    /// fallback. There is no cheap in-process syscall counter for a
    /// unit test (DTrace/`dtruss` sampling needs privileges the test
    /// runner may not have — syscall density is instead measured
    /// out-of-band by the real-machine benchmark), so the proof is
    /// behavioural: tokio's `try_*` calls gate on the reactor's
    /// *cached* readiness and read `WouldBlock` on a socket the driver
    /// never polled, while the raw batch syscalls go straight to the
    /// kernel — a batch that lands *without* arming the readiness
    /// cache can only have come through `sendmsg_x`/`recvmsg_x`.
    ///
    /// The roundtrip itself re-asserts the batch contract: N staged
    /// datagrams, one `send_batch` count of N, one `recv_batch` count
    /// of N, payloads in wire order.
    #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
    #[tokio::test(flavor = "current_thread")]
    async fn send_recv_batch_macos_msgx_roundtrip() {
        let a_sock = std_sock();
        let b_sock = std_sock();
        let b_addr = b_sock.local_addr().expect("addr");
        a_sock.connect(b_addr).expect("connect");
        let a = ep(a_sock, true);
        let b = ep(b_sock, true);

        const N: usize = 12;
        let payloads: Vec<Vec<u8>> = (0..N).map(|i| vec![0x30 + i as u8; 24 + i]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        // No `writable()` arm: `try_send` would cold-gate to zero, so
        // N accepted here is only possible through the raw syscall.
        assert_eq!(
            a.send_batch(&refs, b_addr),
            N,
            "a batch accepted on a never-polled socket is the sendmsg_x proof"
        );

        let mut bufs: Vec<Vec<u8>> = (0..N).map(|_| vec![0u8; 128]).collect();
        // No `readable()` arm either: `recvmsg_x` reads the kernel
        // queue directly — `try_recv_buf` would cold-gate to zero —
        // so every datagram drained here came through the raw syscall
        // on a never-polled socket. Delivery can still be in flight
        // when the first drain runs, so top up across further raw
        // drains — a gated fallback would return 0 forever and trip
        // the deadline, which keeps the cold-gate proof intact.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut n = 0;
        while n < N {
            n += b.recv_batch(&mut bufs[n..], N - n);
            assert!(
                std::time::Instant::now() < deadline,
                "recv_batch stalled at {n}/{N} — a reactor-gated fallback \
                 cold-gates to zero on this never-polled socket"
            );
            tokio::task::yield_now().await;
        }
        for (i, buf) in bufs.iter().enumerate() {
            assert_eq!(buf.as_slice(), &payloads[i][..], "wire order preserved");
        }
    }

    /// The `no-macos-sendmsg-x` opt-out restores the per-datagram
    /// fallback: a `send_batch` on a never-polled socket cold-gates to
    /// zero — the exact inverse of the msgx pin above.
    #[cfg(all(target_os = "macos", feature = "no-macos-sendmsg-x"))]
    #[tokio::test(flavor = "current_thread")]
    async fn no_macos_sendmsg_x_restores_fallback() {
        let a_sock = std_sock();
        let b_addr = std_sock().local_addr().expect("addr");
        a_sock.connect(b_addr).expect("connect");
        let a = ep(a_sock, true);

        let payloads: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 32]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        assert_eq!(
            a.send_batch(&refs, b_addr),
            0,
            "fallback `try_send` cold-gates without armed readiness"
        );
        // Compile-time pin: under this feature the batch calls must
        // not claim the syscall path.
        const _: () = assert!(!BatchEndpoint::BATCHED_SYSCALLS);
    }
}
