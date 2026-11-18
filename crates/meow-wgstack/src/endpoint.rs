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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use meow_common::ProxyPacketConn;
use tokio::sync::{mpsc, Notify};

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

    /// The kernel fd — the bridge thread's blocking `poll` waits on
    /// it directly rather than on tokio's cached readiness.
    #[cfg(unix)]
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.inner.as_raw_fd()
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

    /// Reactor readiness passthroughs the bridge tasks and tests await
    /// before batch calls: every `try_*` gates on the reactor's
    /// *cached* readiness, so a just-registered socket reads
    /// `WouldBlock` until the driver has polled it once. Long-lived
    /// actors never see that window — their select arms poll the
    /// socket before any `try_*` runs.
    pub async fn readable(&self) -> io::Result<()> {
        self.inner.readable().await
    }

    /// See [`readable`](Self::readable).
    pub async fn writable(&self) -> io::Result<()> {
        self.inner.writable().await
    }

    /// `true` on a peer-bound socket — the bridge's boundary retry
    /// picks `try_send`/`try_send_to` on it.
    pub(crate) fn is_connected(&self) -> bool {
        self.connected
    }

    // ── batch calls ──────────────────────────────────────────────

    /// Drain up to `min(bufs.len(), budget, WIRE_DRAIN_BUDGET)`
    /// datagrams — one `recvmmsg` on Linux, `MSGX_CHUNK`-capped
    /// `recvmsg_x` rounds on macOS, a `try_recv_buf` loop elsewhere.
    /// The third clamp is the stack-array bound: a single batched call
    /// can never service more slots than its arrays hold, and the
    /// fallback loop inherits the same bound so both paths agree on
    /// what one call is allowed to do. Every
    /// slot's whole *capacity* is its receive window — never its
    /// current length — so a persistent slot set serves batch after
    /// batch without restaging. On return, each of `bufs[..ret]` is
    /// sized to its datagram; the contents of later slots are
    /// unspecified. This is a connected-peer read: sources are not
    /// reported because the pump's socket only ever receives from the
    /// bound peer.
    ///
    /// Connected endpoints only — on an unconnected socket every
    /// backend reads without a `msg_name`, so a stray peer's datagram
    /// would be silently attributed to the bound peer's stream. Debug
    /// builds assert the flag.
    pub fn recv_batch(&self, bufs: &mut [Vec<u8>], budget: usize) -> usize {
        debug_assert!(
            self.connected,
            "recv_batch drops source addresses — connected endpoints only"
        );
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

    /// The unconnected twin of [`recv_batch`](Self::recv_batch): same
    /// batch-syscall drain, but each header's `msg_name` catches the
    /// datagram's source — the listener demux's key — written into
    /// `addrs[..ret]` alongside `bufs[..ret]`. `addrs.len()` must cover
    /// `bufs`.
    ///
    /// Unconnected endpoints only: a connected socket only ever
    /// receives from its bound peer, so the per-datagram name work is
    /// wasted there (the pump uses `recv_batch`).
    pub fn recv_batch_from(
        &self,
        bufs: &mut [Vec<u8>],
        addrs: &mut [SocketAddr],
        budget: usize,
    ) -> usize {
        debug_assert!(
            !self.connected,
            "recv_batch_from pays per-datagram names — unconnected endpoints only"
        );
        debug_assert!(addrs.len() >= bufs.len());
        let n = bufs.len().min(budget).min(WIRE_DRAIN_BUDGET);
        #[cfg(target_os = "linux")]
        {
            self.recv_batch_mmsg_from(&mut bufs[..n], &mut addrs[..n])
        }
        #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
        {
            self.recv_batch_msgx_from(&mut bufs[..n], &mut addrs[..n])
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", not(feature = "no-macos-sendmsg-x"))
        )))]
        {
            let mut got = 0;
            for (buf, addr) in bufs[..n].iter_mut().zip(&mut addrs[..n]) {
                buf.clear();
                // Extend over the slot's whole spare capacity so the
                // kernel's window matches the batch paths' `iov_len`.
                buf.resize(buf.capacity(), 0);
                match self.inner.try_recv_from(buf) {
                    Ok((m, src)) => {
                        buf.truncate(m);
                        *addr = src;
                        got += 1;
                    }
                    Err(e) => {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            tracing::debug!("wireguard endpoint recv_batch_from error: {e}");
                        }
                        break;
                    }
                }
            }
            got
        }
    }

    /// `recv_batch_mmsg` with per-message `msg_name`: each
    /// `mmsghdr`'s header points at its own `sockaddr_storage`, and
    /// the kernel reports the source the same way `recvmsg` would.
    #[cfg(target_os = "linux")]
    fn recv_batch_mmsg_from(&self, bufs: &mut [Vec<u8>], addrs: &mut [SocketAddr]) -> usize {
        use std::os::fd::AsRawFd;
        let n = bufs.len().min(WIRE_DRAIN_BUDGET);
        let bufs = &mut bufs[..n];
        if bufs.is_empty() {
            return 0;
        }
        // SAFETY: as in `recv_batch_mmsg` — C POD arrays, all-zero
        // valid; the extra `sockaddr_storage` array receives the
        // kernel-written `msg_name` payloads.
        let mut iov: [libc::iovec; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
        let mut sas: [libc::sockaddr_storage; WIRE_DRAIN_BUDGET] = unsafe { std::mem::zeroed() };
        for (j, buf) in bufs.iter_mut().enumerate() {
            iov[j] = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.capacity(),
            };
            msgs[j].msg_hdr.msg_iov = &mut iov[j];
            msgs[j].msg_hdr.msg_iovlen = 1;
            msgs[j].msg_hdr.msg_name = (&mut sas[j]) as *mut _ as *mut _;
            msgs[j].msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        }
        // SAFETY: as in `recv_batch_mmsg` — `sas` slots are valid for
        // the kernel's sockaddr writes for the call's duration.
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
            // SAFETY: as in `recv_batch_mmsg`.
            unsafe { buf.set_len(len) };
            addrs[j] = read_sockaddr(&sas[j]);
        }
        got
    }

    /// `recv_batch_msgx` with per-message `msg_name` — the unconnected
    /// listener's batched drain on Darwin.
    #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
    fn recv_batch_msgx_from(&self, bufs: &mut [Vec<u8>], addrs: &mut [SocketAddr]) -> usize {
        use std::os::fd::AsRawFd;
        let mut total = 0usize;
        while total < bufs.len() {
            let n = (bufs.len() - total).min(Self::MSGX_CHUNK);
            let chunk = &mut bufs[total..total + n];
            // SAFETY: as in `recv_batch_msgx` — C POD arrays, all-zero
            // valid; `sas` catches each datagram's source.
            let mut iov: [libc::iovec; Self::MSGX_CHUNK] = unsafe { std::mem::zeroed() };
            let mut msgs: [msgx::msghdr_x; Self::MSGX_CHUNK] = unsafe { std::mem::zeroed() };
            let mut sas: [libc::sockaddr_storage; Self::MSGX_CHUNK] = unsafe { std::mem::zeroed() };
            for (j, buf) in chunk.iter_mut().enumerate() {
                iov[j] = libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: buf.capacity(),
                };
                msgs[j].msg_iov = &mut iov[j];
                msgs[j].msg_iovlen = 1;
                msgs[j].msg_name = (&mut sas[j]) as *mut _ as *mut _;
                msgs[j].msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            }
            // SAFETY: as in `recv_batch_msgx`.
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
                break;
            }
            let got = ret as usize;
            for (j, buf) in chunk[..got].iter_mut().enumerate() {
                let len = msgs[j].msg_datalen.min(buf.capacity());
                // SAFETY: as in `recv_batch_msgx`.
                unsafe { buf.set_len(len) };
                addrs[total + j] = read_sockaddr(&sas[j]);
            }
            total += got;
            // A short round is the dry-queue report — stop rather than
            // spend a syscall confirming it.
            if got < n {
                break;
            }
        }
        total
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

    /// Per-`sendmsg_x`/`recvmsg_x` datagram ceiling: XNU clips each
    /// call's count at `somaxsendmsgx`/`somaxrecvmsgx` (default 100 —
    /// see `msgx`), so a [`WIRE_DRAIN_BUDGET`]-sized batch is serviced
    /// in chunks of at most this many headers where Linux spends one
    /// `sendmmsg`/`recvmmsg`. The `min` keeps the batch a single call
    /// should the budget ever drop back under the kernel's ceiling.
    #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
    const MSGX_CHUNK: usize = if WIRE_DRAIN_BUDGET < 100 {
        WIRE_DRAIN_BUDGET
    } else {
        100
    };

    /// macOS: `sendmsg_x` over stack-built `msghdr_x`/`iovec` arrays —
    /// the same shape as the Linux `sendmmsg` path, chunked at
    /// `MSGX_CHUNK`. On a connected UDP socket XNU takes the
    /// `sendit_x`/`sosend_list` fast path (no per-datagram name); on an
    /// unconnected one each header's `msg_name` carries its
    /// destination and the kernel loops `sendit` — still one syscall
    /// per chunk, per-datagram addressing preserved.
    #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
    fn send_batch_inner<T>(&self, pkts: &[T], get: impl Fn(&T) -> (SocketAddr, &[u8])) -> usize {
        use std::os::fd::AsRawFd;
        let mut sent = 0usize;
        while sent < pkts.len() {
            let n = (pkts.len() - sent).min(Self::MSGX_CHUNK);
            // SAFETY: `iovec`, `msghdr_x` and `sockaddr_storage` are C
            // PODs — the all-zero bit pattern is valid for every field
            // (null pointer, zero length, family AF_UNSPEC) and zeroed
            // `msg_flags`/`msg_datalen` are the input values
            // `sendmsg_x` requires.
            let mut iov: [libc::iovec; Self::MSGX_CHUNK] = unsafe { std::mem::zeroed() };
            let mut msgs: [msgx::msghdr_x; Self::MSGX_CHUNK] = unsafe { std::mem::zeroed() };
            let mut sas: [libc::sockaddr_storage; Self::MSGX_CHUNK] = unsafe { std::mem::zeroed() };
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

    /// One or more `recvmsg_x` rounds into the staged buffers — XNU's
    /// batched `soreceive_m_list`, which stops when the socket queue
    /// runs dry under `MSG_DONTWAIT` and reports each datagram's
    /// received length in `msg_datalen` (bytes actually copied, ≤ the
    /// advertised iov capacity). Each round is capped at `MSGX_CHUNK`
    /// headers — XNU's per-call clip — so a batch wider than the clip
    /// loops until a short round reports the queue dry; `msgs[..got]`
    /// of each round is the only span the kernel rewrote.
    #[cfg(all(target_os = "macos", not(feature = "no-macos-sendmsg-x")))]
    fn recv_batch_msgx(&self, bufs: &mut [Vec<u8>]) -> usize {
        use std::os::fd::AsRawFd;
        let mut total = 0usize;
        while total < bufs.len() {
            let n = (bufs.len() - total).min(Self::MSGX_CHUNK);
            let chunk = &mut bufs[total..total + n];
            // SAFETY: as in `send_batch_inner` — C POD arrays, all-zero
            // valid; `recvmsg_x` requires zeroed `msg_flags` on input.
            let mut iov: [libc::iovec; Self::MSGX_CHUNK] = unsafe { std::mem::zeroed() };
            let mut msgs: [msgx::msghdr_x; Self::MSGX_CHUNK] = unsafe { std::mem::zeroed() };
            for (j, buf) in chunk.iter_mut().enumerate() {
                iov[j] = libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: buf.capacity(),
                };
                msgs[j].msg_iov = &mut iov[j];
                msgs[j].msg_iovlen = 1;
            }
            // SAFETY: `fd` is a live nonblocking socket; `msgs`
            // describes `n` iovecs each covering that Vec's whole
            // allocation, initialised or not — writes through the raw
            // pointer are in-bounds and no Rust reference aliases them.
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
                break;
            }
            let got = ret as usize;
            for (j, buf) in chunk[..got].iter_mut().enumerate() {
                let len = msgs[j].msg_datalen.min(buf.capacity());
                // SAFETY: the kernel wrote the first `msg_datalen`
                // bytes of `buf`'s allocation (datalen is the copied
                // count, ≤ the advertised capacity), so those bytes
                // are initialised and extending `len` over them is
                // sound.
                unsafe { buf.set_len(len) };
            }
            total += got;
            // A short round is the dry-queue report — stop rather than
            // spend a syscall confirming it.
            if got < n {
                break;
            }
        }
        total
    }
}

/// Bounded queue depth of a [`ProxyEndpoint`]'s two bridge channels, in
/// datagrams. Sized to four full wire drains so one whole
/// [`Endpoint::recv_batch`] burst — or the symmetric staged
/// [`Endpoint::send_batch`] flush — never meets a full queue mid-pass:
/// back-pressure surfaces as `WouldBlock` only past that, exactly where
/// the socket path's `ENOBUFS`/`EAGAIN` would. Four rather than two:
/// the bridge is also the front hop's jitter absorber, and a burst
/// arriving mid-pass must not drop while this pass's drain is still
/// staged (wg-perf, paired with the `WIRE_DRAIN_BUDGET` raise).
const PROXY_ENDPOINT_QUEUE: usize = 4 * WIRE_DRAIN_BUDGET;

/// The coalescing bound on the RX thread's side: after a short
/// `recv_batch` the socket is nearly dry, so re-poll briefly for more
/// arrivals instead of spending a fresh `poll`+`recvmsg_x` round on
/// every straggler.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
const RX_COALESCE_USEC: libc::useconds_t = 200;

/// Accumulation sleep after a short drain: parks the bridge thread for
/// `RX_COALESCE_USEC` so the next `recv_batch` sees a deeper socket
/// queue. Readiness is not re-checked — under a continuous stream the
/// window itself is the coalescer, and a dry follow-up batch exits the
/// drain loop back onto the parked `poll`.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn rx_coalesce() {
    unsafe { libc::usleep(RX_COALESCE_USEC) };
}

/// Staging buffer of the [`ProxyEndpoint`] RX bridge — one full UDP
/// payload. WG wire datagrams stay far below this (outer MTU +
/// overhead); the bound only keeps a pathological conn read inside the
/// slice, same role as the socket's own 64 KiB ceiling.
const BRIDGE_BUF: usize = 65535;

/// Per-datagram bound on a TX-bridge `conn.write_packet`. A front hop
/// whose async write stalls on flow control or a half-dead transport
/// would otherwise pin the bridge task — and its `Arc` refs on the conn
/// and the RX queue — past teardown. The bound is generous (well past
/// WG's handshake retry cadence): a slow-but-alive front keeps writing,
/// while a truly wedged one drops the task so the conn can close and
/// the pump's `is_proxy_dead` redial take over. WG is datagram
/// transport, so cancelling a mid-flight write corrupts nothing — each
/// packet is independent, unlike a stream's `PoisonOnIncomplete`.
const PROXY_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The outbound pump's wire endpoint: `Batch` is the direct path (a
/// connected kernel socket behind a [`BridgedEndpoint`]'s own I/O
/// tasks), `Proxy` a [`ProxyEndpoint`] bridged to a `dialer-proxy`
/// front's `ProxyPacketConn` (issue #899 — the WG endpoint's UDP
/// transport rides the front hop's UDP association).
///
/// An enum, not a trait object: the method set is closed, both variants
/// sit on the hot drain/flush path, and enum dispatch keeps the direct
/// path free of a vtable it never needed.
pub enum Endpoint {
    /// A connected kernel socket — the direct path.
    Batch(BridgedEndpoint),
    /// A channel pair bridged to an async `ProxyPacketConn`.
    Proxy(ProxyEndpoint),
}

impl Endpoint {
    /// Nonblocking single-datagram receive — the pump's fast-path drain.
    ///
    /// Both arms pop a bridge RX queue — `Empty` → `WouldBlock`,
    /// `Disconnected` → `ConnectionReset` (the RX bridge exited on a
    /// dead conn/socket — terminal: the pump's `recv` arm stops the
    /// actor, and `ensure_pump`'s `is_proxy_dead` check clears the
    /// slot and redials).
    pub fn try_recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Endpoint::Batch(e) => e.try_recv(buf),
            Endpoint::Proxy(e) => e.try_recv(buf),
        }
    }

    /// Async single-datagram receive — the pump's `select!` driver.
    ///
    /// `Proxy`: awaits the bridge RX queue; a closed queue (conn dead or
    /// the RX bridge exited) maps to `ConnectionReset`.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Endpoint::Batch(e) => e.recv(buf).await,
            Endpoint::Proxy(e) => e.recv(buf).await,
        }
    }

    /// Drain up to `min(bufs.len(), budget, WIRE_DRAIN_BUDGET)`
    /// datagrams into the staged slots — same leading-count contract as
    /// [`BatchEndpoint::recv_batch`]: each of `bufs[..ret]` is sized to
    /// its datagram, slot capacity survives for the next batch.
    pub fn recv_batch(&mut self, bufs: &mut [Vec<u8>], budget: usize) -> usize {
        match self {
            Endpoint::Batch(e) => e.recv_batch(bufs, budget),
            Endpoint::Proxy(e) => e.recv_batch(bufs, budget),
        }
    }

    /// Nonblocking single-datagram send — `WouldBlock` means "requeue
    /// and stop", matching the socket's `EAGAIN` semantics the pump's
    /// `flush_outbox` already keys on.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Endpoint::Batch(e) => e.try_send(buf),
            Endpoint::Proxy(e) => e.try_send(buf),
        }
    }

    /// Send every datagram to the bound peer, returning the leading
    /// accepted count. `addr` is advisory on a connected endpoint —
    /// `Proxy` ignores it entirely (the TX bridge stamps the endpoint
    /// address captured at construction onto each `write_packet`, which
    /// is what per-packet conns like SS UDP need in their header).
    ///
    /// `Proxy` degrades the batch to a `try_send` loop — expected, not a
    /// fallback: the front hop serializes datagrams anyway, so batch
    /// syscalls would buy nothing.
    pub fn send_batch(&self, pkts: &[&[u8]], addr: SocketAddr) -> usize {
        match self {
            Endpoint::Batch(e) => e.send_batch(pkts, addr),
            Endpoint::Proxy(e) => e.send_batch(pkts, addr),
        }
    }

    /// The local address of the endpoint socket / front-hop conn.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Endpoint::Batch(e) => e.local_addr(),
            Endpoint::Proxy(e) => Ok(e.local_addr()),
        }
    }
}

/// A [`Notify`] pulse armed on drop — the TX bridge task's exit edge
/// into its RX twin. Held as a local of the TX task's async block so
/// *every* exit path (queue close, write error, `PROXY_WRITE_TIMEOUT`,
/// the `shutdown_tx` drop edge) fires `shutdown_rx` at scope end —
/// right after `conn.close()` ran. `close()` alone cannot reach the
/// RX task's parked `read_packet` on the Raw `ProxyPacketConn`s
/// (`DirectPacketConn`, `Socks5UdpTransport::Raw`, `SsUdpIo::Raw`,
/// `ConnectedUdpConn`), where it is a no-op: without the pulse the RX
/// task outlived a dead TX side forever, `wire_tx` never dropped, and
/// the pump's `recv` never saw the channel close — no
/// `ConnectionReset`, no `is_proxy_dead` redial, and a warn-per-packet
/// storm on the send path while the dead front hop blackholed
/// datagrams.
struct NotifyOnDrop(Arc<Notify>);

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

/// A one-byte wake signal for the RX thread's `poll`: the read end
/// sits in its fd set, the write end lives in [`RxStop`]. `send` with
/// `MSG_NOSIGNAL` so a `stop()` landing after the thread already
/// exited (read end closed) is a harmless `EPIPE`, never a fatal
/// `SIGPIPE` to the process.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
struct WakeFd(std::os::fd::RawFd);

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
impl WakeFd {
    /// `(write end, read end)` — write lives in `RxStop`, read is
    /// handed to the thread (which owns and closes it on exit).
    fn pair() -> (Arc<Self>, std::os::fd::RawFd) {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert!(rc == 0, "wg-rx wake socketpair");
        #[cfg(target_os = "macos")]
        {
            // Darwin honors `MSG_NOSIGNAL` per-send; `SO_NOSIGPIPE`
            // on the write end is the platform's canonical knob —
            // belt-and-suspenders so no call-site flag is load-bearing.
            let on: i32 = 1;
            let rc = unsafe {
                libc::setsockopt(
                    fds[1],
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&on) as libc::socklen_t,
                )
            };
            assert!(rc == 0, "SO_NOSIGPIPE on wg-rx wake socket");
        }
        (Arc::new(Self(fds[1])), fds[0])
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
impl Drop for WakeFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// `BridgedEndpoint`'s RX-leg stop edge — every shape at once so the
/// struct and its `Drop` never care which leg the platform spawned:
/// the dedicated OS thread polls `flag` between kernel waits *and* is
/// woken out of `poll` by a byte on `wake`, the tokio task `select!`s
/// on `pulse`. `stop()` fires all three.
#[derive(Clone)]
struct RxStop {
    flag: Arc<AtomicBool>,
    pulse: Arc<Notify>,
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    wake: Option<Arc<WakeFd>>,
}

impl RxStop {
    fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            pulse: Arc::new(Notify::new()),
            #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
            wake: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    fn with_wake(wake: Arc<WakeFd>) -> Self {
        let mut s = Self::new();
        s.wake = Some(wake);
        s
    }

    fn stop(&self) {
        self.flag.store(true, Ordering::Relaxed);
        self.pulse.notify_one();
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        if let Some(w) = &self.wake {
            unsafe {
                libc::send(w.0, [1u8].as_ptr().cast(), 1, libc::MSG_NOSIGNAL);
            }
        }
    }
}

/// `NotifyOnDrop`'s sibling for the [`RxStop`] edge the `BridgedEndpoint`
/// RX leg watches: the TX task holds one so its exit flags the RX
/// bridge down the same way endpoint `Drop` does.
struct RxStopOnDrop(RxStop);

impl Drop for RxStopOnDrop {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// A [`ProxyPacketConn`] (async) bridged onto the pump's synchronous
/// `try_recv`/`try_send`/`recv`/`recv_batch`/`send_batch` surface by two
/// bounded mpsc queues and two tokio bridge tasks spawned at
/// construction:
///
/// - **RX task** loops `conn.read_packet` → `wire_tx.send(Bytes)`; a
///   conn error exits the task, dropping the sender — the pump's next
///   `try_recv`/`recv` sees `Disconnected`/`None` → `ConnectionReset`,
///   the terminal signal that stops the actor for `ensure_pump` to
///   redial. A [`Notify`] edge lets `drop` interrupt a parked
///   `read_packet` instead of waiting for the conn.
/// - **TX task** races `pump_rx.recv` against its own [`Notify`] drop
///   edge, then races each `conn.write_packet(&pkt, &endpoint_addr)`
///   against the same edge under a `PROXY_WRITE_TIMEOUT` bound —
///   two selects, so a stalled in-flight write can still be cancelled:
///   a write error or a wedged write exits the task (a dead front conn
///   is terminal — draining the queue would only blackhole datagrams),
///   as do queue close (pump teardown) and the drop edge. Every exit
///   calls `conn.close()` and then — via a `NotifyOnDrop` guard held
///   for the block's scope — pulses `shutdown_rx`, so TX death reaches
///   the parked `read_packet` even on conns whose `close()` is a no-op.
pub struct ProxyEndpoint {
    /// Inbound wire: datagrams the RX bridge pulled off the front conn.
    rx: mpsc::Receiver<Bytes>,
    /// Outbound wire: datagrams the TX bridge hands to the front conn.
    tx: mpsc::Sender<Bytes>,
    /// Cached `conn.local_addr()` — the bound port of the front conn.
    local_addr: SocketAddr,
    /// Drop edge for the RX bridge — a parked `read_packet` would
    /// otherwise outlive the endpoint until the conn reports.
    shutdown_rx: Arc<Notify>,
    /// Drop edge for the TX bridge — interrupts a `write_packet`
    /// stalled past its timeout that the `pump_rx` close alone cannot
    /// reach. A second `Notify`, not a share of the RX edge:
    /// `notify_one` wakes a single waiter, so one shared edge could
    /// leave one bridge task unpulsed; two edges each hold their own
    /// stored permit and both tasks see the drop, parked or just about
    /// to park.
    shutdown_tx: Arc<Notify>,
    /// A reference on the front conn — the endpoint owns it as long as
    /// it lives (the two bridge tasks share the other refs).
    _conn: Arc<dyn ProxyPacketConn>,
    /// The two bridge tasks; kept only so their lifetime reads as owned
    /// by the endpoint (each is self-terminating on channel close).
    _bridge: (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>),
}

impl ProxyEndpoint {
    /// Build the endpoint and spawn both bridge tasks. Must be called
    /// from a tokio runtime context (`tokio::spawn` inside); the
    /// adapter's `ensure_pump` is async so this is always true.
    ///
    /// `endpoint_addr` is the destination stamped on every
    /// `write_packet` — for per-packet conns (SS UDP) it is what lands
    /// in the relay header, so callers pass the real target
    /// (`UdpTarget::write_dst`), not a placeholder.
    pub fn new(
        conn: Arc<dyn ProxyPacketConn>,
        endpoint_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Self {
        let (wire_tx, wire_rx) = mpsc::channel::<Bytes>(PROXY_ENDPOINT_QUEUE);
        let (pump_tx, pump_rx) = mpsc::channel::<Bytes>(PROXY_ENDPOINT_QUEUE);
        let shutdown_rx = Arc::new(Notify::new());
        let shutdown_tx = Arc::new(Notify::new());

        let rx_task = tokio::spawn({
            let conn = Arc::clone(&conn);
            let shutdown = Arc::clone(&shutdown_rx);
            async move {
                let mut buf = vec![0u8; BRIDGE_BUF];
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.notified() => break,
                        r = conn.read_packet(&mut buf) => match r {
                            Ok((n, _src)) => {
                                if wire_tx
                                    .send(Bytes::copy_from_slice(&buf[..n]))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            // conn dead → drop the queue's sender so the
                            // pump sees Disconnected → ConnectionReset.
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        let tx_task = tokio::spawn({
            let conn = Arc::clone(&conn);
            let shutdown = Arc::clone(&shutdown_tx);
            let rx_pulse = NotifyOnDrop(Arc::clone(&shutdown_rx));
            async move {
                // Dropped at scope end — after `conn.close()` below —
                // on *every* exit path, pulsing `shutdown_rx` so the
                // RX bridge unwinds its parked `read_packet`: the kill
                // edge `close()` cannot provide on Raw conns (see
                // `NotifyOnDrop`).
                let _rx_pulse = rx_pulse;
                let mut pump_rx = pump_rx;
                loop {
                    // Two selects, not one: a `write_packet` awaited
                    // *inside* a select arm runs outside the race —
                    // the drop edge could never cancel it. Racing the
                    // write itself against `notified()` is what lets a
                    // stalled write unwind on teardown; the
                    // `pump_rx` close alone cannot reach into an
                    // in-flight write.
                    let pkt = tokio::select! {
                        biased;
                        _ = shutdown.notified() => break,
                        pkt = pump_rx.recv() => {
                            let Some(pkt) = pkt else { break };
                            pkt
                        }
                    };
                    // A failed front-hop write is terminal for this
                    // conn — no transient/permanent split, no retry
                    // threshold: WG is a datagram transport, so a lost
                    // packet is ordinary (the Noise layer retransmits
                    // on its own cadence), and the errnos a write-side
                    // retry could outlive (`EHOSTUNREACH`, `EPERM`) do
                    // not self-heal inside one. The recovery unit is
                    // `ensure_pump`'s conn redial, reached through
                    // `_rx_pulse` → `ConnectionReset`; draining the
                    // rest of the queue would only blackhole datagrams
                    // until the pump gets there.
                    let r = tokio::select! {
                        biased;
                        _ = shutdown.notified() => break,
                        r = tokio::time::timeout(
                            PROXY_WRITE_TIMEOUT,
                            conn.write_packet(&pkt, &endpoint_addr),
                        ) => r,
                    };
                    match r {
                        Ok(Ok(_)) => {}
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
                let _ = conn.close();
            }
        });

        Self {
            rx: wire_rx,
            tx: pump_tx,
            local_addr,
            shutdown_rx,
            shutdown_tx,
            _conn: conn,
            _bridge: (rx_task, tx_task),
        }
    }

    /// See [`Endpoint::try_recv`].
    fn try_recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rx.try_recv() {
            Ok(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
    }

    /// See [`Endpoint::recv`].
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rx.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::from(io::ErrorKind::ConnectionReset)),
        }
    }

    /// See [`Endpoint::recv_batch`].
    fn recv_batch(&mut self, bufs: &mut [Vec<u8>], budget: usize) -> usize {
        let n = bufs.len().min(budget).min(WIRE_DRAIN_BUDGET);
        let mut got = 0;
        for buf in &mut bufs[..n] {
            match self.rx.try_recv() {
                Ok(pkt) => {
                    // The slot's whole capacity is its receive window —
                    // same contract as the socket path.
                    buf.clear();
                    let take = pkt.len().min(buf.capacity());
                    buf.extend_from_slice(&pkt[..take]);
                    got += 1;
                }
                Err(_) => break,
            }
        }
        got
    }

    /// See [`Endpoint::try_send`].
    fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        match self.tx.try_send(Bytes::copy_from_slice(buf)) {
            Ok(()) => Ok(buf.len()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
    }

    /// See [`Endpoint::send_batch`]. The `addr` arg is ignored — the TX
    /// bridge holds the stamped destination from construction.
    fn send_batch(&self, pkts: &[&[u8]], _addr: SocketAddr) -> usize {
        let mut sent = 0;
        for pkt in pkts {
            match self.tx.try_send(Bytes::copy_from_slice(pkt)) {
                Ok(()) => sent += 1,
                Err(_) => break,
            }
        }
        sent
    }

    /// See [`Endpoint::local_addr`].
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for ProxyEndpoint {
    /// Pulse both bridge select arms so a parked `read_packet` or a
    /// stalled `write_packet` unwinds promptly. Each task owns a
    /// separate `Notify` — a single `notify_one` wakes only one waiter,
    /// so a shared edge could strand one of the two; the stored permit
    /// also covers a task that parks on `notified()` just after this
    /// pulse. The TX task's secondary exit is the `pump_tx` close on
    /// the field teardown right below (it calls `conn.close()` on the
    /// way out).
    fn drop(&mut self) {
        self.shutdown_rx.notify_one();
        self.shutdown_tx.notify_one();
    }
}

/// The RX bridge's per-wait drain bound. A still-busy socket reports
/// `POLLIN` again the moment `poll` re-arms, so the cap only costs a
/// wait round — and it keeps the `shutdown` edge honest under a
/// permanent flood. Sized to the bridge queue: one wake can fill the
/// channel exactly once before backpressure parks the `send` anyway.
const RX_WAKE_CAP: usize = BRIDGE_RX_QUEUE;

/// The RX channel's depth — deliberately deeper than the TX side's
/// `PROXY_ENDPOINT_QUEUE`. Channel-buffered datagrams can never be
/// lost (a full channel just parks the bridge's `send` and pushes
/// backpressure onto `SO_RCVBUF`), while kernel-buffered ones tail-
/// drop under a peer burst. The RX window between `drain_wire` calls
/// is one service pass — milliseconds of smoltcp/crypto/TX work —
/// and the kernel buffer alone (≤8 MiB) does not always cover a
/// ~4×`WIRE_DRAIN_BUDGET` channel plus that window's arrivals. The
/// startup burst is the binding case: N inner flows' first advertised
/// windows (~1 MiB each) can all land inside one pass-length window,
/// so the channel is sized `32 * WIRE_DRAIN_BUDGET` (~11.4 MiB staged)
/// — kernel+channel covers roughly a 19 MiB aggregate burst — moving
/// absorption out of the droppable kernel buffer into the bounded
/// channel; TX stays shallow on purpose — a
/// deeper send queue would just assemble bigger `send_batch` bursts
/// that overflow the *peer's* kernel buffer the same way.
const BRIDGE_RX_QUEUE: usize = 32 * WIRE_DRAIN_BUDGET;

/// Receive-slot capacity of the connected RX bridge's `recv_batch`
/// staging: WG wire datagrams are MTU-bound (~1.5 KiB plus outer
/// overhead); `BRIDGE_BUF`'s full-datagram bound would make a
/// [`WIRE_DRAIN_BUDGET`]-slot stage a 16 MiB allocation.
const BRIDGE_SLOT: usize = 4096;

/// A [`BatchEndpoint`] moved off the actor's service pass into two
/// dedicated I/O tasks — the [`ProxyEndpoint`] shape applied to the
/// kernel socket itself, closing the duplex-collapse gap the
/// front-hop bridge already proved.
///
/// Why it exists: a pass spends milliseconds on wire crypto, smoltcp
/// servicing and TX emission *between* kernel-buffer drains. A peer
/// burst that outruns the pass keeps `SO_RCVBUF` full for most of that
/// window, so the kernel tail-drops wire datagrams — each an
/// unrecoverable inner-TCP hole that costs ≥1 s of RTO. Upload-only
/// and download-only tests hide it (one direction idles while the
/// other drains); duplex saturates both, and the pass-serialised
/// drains on *both* ends overflow simultaneously. The bridge runs the
/// kernel I/O on readiness — µs-scale drain latency, independent of
/// pass length:
///
/// - **RX thread** — a dedicated OS thread, not a runtime task —
///   parks on `poll(fd)` then drains the socket into a bounded
///   channel: `recv_batch` rounds on a connected socket,
///   `recv_batch_from` on an unconnected one (the listener demux needs
///   each source). Owning the drain in a thread removes the last
///   scheduling hop: tokio can queue a woken task behind a
///   synchronous actor pass on the same worker, and that stall alone
///   was still overflowing `SO_RCVBUF` under wire bursts with the
///   channel never full. A full channel parks `blocking_send` —
///   pressure falls back onto `SO_RCVBUF`, the designed absorber,
///   instead of unbounded memory.
/// - **TX task** drains a bounded channel with batched socket sends,
///   replaying the short-count boundary datagram with `try_send*` to
///   split `WouldBlock` (await `writable`, retry) from a real errno
///   (log, drop *that* datagram, continue — the kernel-error verdict
///   `flush_outbox` used to own lives here now, where the error is
///   actually visible). Channel-full reaches the caller as the same
///   `WouldBlock` a busy socket reported, so `flush_outbox`'s requeue
///   path is unchanged.
///
/// Datagram ordering is end-to-end FIFO: the socket delivers in order,
/// the channels are FIFO, and the TX task emits in channel order.
/// Teardown mirrors [`ProxyEndpoint`]: an `RxStop` edge for the RX
/// leg, a [`Notify`] edge for the TX task, and the TX task's
/// `RxStopOnDrop` flags the RX edge so a dead twin never leaves the
/// leg parked on a quiet socket.
pub struct BridgedEndpoint {
    /// Wire RX: `(src, datagram)` pairs the RX bridge pulled off the
    /// socket. On a connected socket `src` is the bound peer (the
    /// kernel delivers no other source).
    rx: mpsc::Receiver<(SocketAddr, Bytes)>,
    /// Wire TX: `(dst, datagram)` pairs for the TX bridge. `dst` is
    /// advisory on a connected socket — `send()` semantics ignore it.
    tx: mpsc::Sender<(SocketAddr, Bytes)>,
    /// The bound peer stamped on `try_send`/`send_batch` channel items
    /// and on connected RX sources; `None` on an unconnected endpoint,
    /// where `try_send` reports `NotConnected` like a std socket.
    peer: Option<SocketAddr>,
    /// Drop edge for the RX leg — flag-polled by the dedicated
    /// thread, `select!`ed by the tokio-task fallback ([`RxStop`]).
    shutdown_rx: RxStop,
    /// Drop edge for the TX bridge's parked `recv`/`writable()`.
    shutdown_tx: Arc<Notify>,
    /// The kernel socket, shared with both bridge halves — also the
    /// `local_addr` source.
    endpoint: Arc<BatchEndpoint>,
    /// The bridge workers; kept so their lifetime reads as owned by
    /// the endpoint (each is self-terminating on channel close or the
    /// shutdown edge). RX is an OS thread where `libc::poll` reaches
    /// the fd (Linux/Android/macOS — the `libc` dependency platforms)
    /// and a tokio task everywhere else; TX is a runtime task. `Drop`
    /// `take`s the RX handle to join it — the socket must actually be
    /// released when teardown returns, not ~50 ms later.
    _bridge: (Option<RxJoin>, tokio::task::JoinHandle<()>),
}

/// The RX leg's join handle — one variant per platform leg:
/// [`Os`](Self::Os) is the dedicated `poll`-parked thread,
/// [`Tokio`](Self::Tokio) the `readable().await` task that runs
/// where `libc` isn't a dependency (the pre-thread behaviour, so
/// nothing regresses on platforms the thread never reached).
#[allow(
    dead_code,
    reason = "held for ownership only — dropping the \
    handle detaches the leg, which is intentional; nothing joins it"
)]
enum RxJoin {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    Os(std::thread::JoinHandle<()>),
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    Tokio(tokio::task::JoinHandle<()>),
}

impl BridgedEndpoint {
    /// Bridge a socket bound to one peer (the outbound pump).
    /// `peer` stamps the source reported for every received datagram —
    /// `recv_batch` discards kernel names, and a connected socket can
    /// only have received from that peer anyway.
    pub fn connected(socket: tokio::net::UdpSocket, peer: SocketAddr) -> Self {
        Self::spawn(BatchEndpoint::connected(socket), Some(peer))
    }

    /// Bridge an unconnected socket (the inbound listener): every
    /// datagram's real source rides the RX channel for peer demux.
    pub fn unconnected(socket: tokio::net::UdpSocket) -> Self {
        Self::spawn(BatchEndpoint::unconnected(socket), None)
    }

    /// Build the channel pair and spawn both bridge tasks. Must be
    /// called from a tokio runtime context — same contract as
    /// [`ProxyEndpoint::new`].
    fn spawn(ep: BatchEndpoint, peer: Option<SocketAddr>) -> Self {
        let ep = Arc::new(ep);
        let (wire_tx, wire_rx) = mpsc::channel(BRIDGE_RX_QUEUE);
        let (pump_tx, pump_rx) = mpsc::channel(PROXY_ENDPOINT_QUEUE);
        let shutdown_tx = Arc::new(Notify::new());

        let (rx_join, shutdown_rx) = Self::spawn_rx(&ep, peer, wire_tx);

        let tx_task = tokio::spawn({
            let ep = Arc::clone(&ep);
            let shutdown = Arc::clone(&shutdown_tx);
            let rx_pulse = RxStopOnDrop(shutdown_rx.clone());
            async move {
                // Flags the RX leg after the loop on *every* exit —
                // see `RxStopOnDrop`.
                let _rx_pulse = rx_pulse;
                let mut pump_rx = pump_rx;
                let mut sendq: Vec<(SocketAddr, Bytes)> = Vec::new();
                'outer: loop {
                    // Wait for the first packet, then take up to one
                    // wire drain of ready packets without adding a timer.
                    let count = tokio::select! {
                        biased;
                        _ = shutdown.notified() => break,
                        n = pump_rx.recv_many(&mut sendq, WIRE_DRAIN_BUDGET) => n,
                    };
                    if count == 0 {
                        break;
                    }
                    let mut sent = 0;
                    while sent < count {
                        sent += ep
                            .send_batch_inner(&sendq[sent..], |(addr, pkt)| (*addr, pkt.as_ref()));
                        let Some((addr, pkt)) = sendq.get(sent) else {
                            break;
                        };
                        // The short-count boundary datagram gets the
                        // per-packet retry — `WouldBlock` parks on
                        // `writable()` and preserves queue order; any
                        // real errno drops just this datagram (the
                        // EMSGSIZE-class rejection `flush_outbox` once
                        // handled — now reported where it happens).
                        let boundary = if ep.is_connected() {
                            ep.try_send(pkt)
                        } else {
                            ep.try_send_to(pkt, *addr)
                        };
                        match boundary {
                            Ok(_) => {
                                sent += 1;
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                let w = tokio::select! {
                                    biased;
                                    _ = shutdown.notified() => break 'outer,
                                    r = ep.writable() => r,
                                };
                                if w.is_err() {
                                    break 'outer;
                                }
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "wireguard endpoint send error (datagram dropped): {e}"
                                );
                                sent += 1;
                            }
                        }
                    }
                    sendq.clear();
                }
            }
        });

        Self {
            rx: wire_rx,
            tx: pump_tx,
            peer,
            shutdown_rx,
            shutdown_tx,
            endpoint: ep,
            _bridge: (Some(rx_join), tx_task),
        }
    }

    /// RX leg, dedicated-thread variant — everywhere `libc` is a
    /// dependency. A dedicated OS thread owns the kernel drain — not
    /// a runtime task. Tokio can queue a woken task behind a
    /// synchronous actor pass on the same worker, and every
    /// millisecond the socket goes unread is kernel buffer a wire
    /// burst turns into drops (observed: channel never full, Recv-Q
    /// still overflowed — the bridge itself, not the channel, was the
    /// stall). A `poll` on the raw fd parks the thread on kernel
    /// state directly: no scheduler stands between the wire and the
    /// drain. `blocking_send` is the same backpressure edge the async
    /// `send().await` was — the channel-full park moves from executor
    /// bookkeeping to a plain futex.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    fn spawn_rx(
        ep: &Arc<BatchEndpoint>,
        peer: Option<SocketAddr>,
        wire_tx: mpsc::Sender<(SocketAddr, Bytes)>,
    ) -> (RxJoin, RxStop) {
        // The wake socketpair lets `stop()` interrupt `poll`
        // immediately — `Drop` joins the thread and teardown cannot
        // return while the socket fd is still owned (the
        // `listener_shutdown_drain` port-rebind contract).
        let (wake_w, wake_r) = WakeFd::pair();
        let stop = RxStop::with_wake(wake_w);
        let shutdown = stop.clone();
        let join = std::thread::Builder::new()
            .name("wg-rx-bridge".into())
            .spawn({
                let ep = Arc::clone(ep);
                move || {
                    // Both socket shapes batch the kernel drain —
                    // `recv_batch` connected, `recv_batch_from`
                    // unconnected (the listener's demux keeps every
                    // real source) — then one `try_recv*` tail confirms
                    // a short batch really means dry and catches a
                    // straggler that landed mid-drain.
                    let mut staged: Vec<Vec<u8>> = (0..WIRE_DRAIN_BUDGET)
                        .map(|_| Vec::with_capacity(BRIDGE_SLOT))
                        .collect();
                    let mut staged_addrs: Vec<SocketAddr> =
                        vec![
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                            WIRE_DRAIN_BUDGET
                        ];
                    'outer: loop {
                        // Wait on the fd itself *and* the wake edge;
                        // the timeout only bounds how often the
                        // shutdown flag is re-checked if the byte is
                        // ever lost. `poll` returns early with `-1` on
                        // a caught signal — re-poll on EINTR instead of
                        // falling through to a WouldBlock drain
                        // round-trip. POLLERR/POLLHUP/POLLNVAL
                        // deliberately fall through: `try_recv*` below
                        // surfaces a persistent fd error as terminal.
                        let mut pfds = [
                            libc::pollfd {
                                fd: ep.raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            },
                            libc::pollfd {
                                fd: wake_r,
                                events: libc::POLLIN,
                                revents: 0,
                            },
                        ];
                        while unsafe { libc::poll(pfds.as_mut_ptr(), 2, 50) } < 0 {
                            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                                break;
                            }
                            for p in &mut pfds {
                                p.revents = 0;
                            }
                        }

                        if shutdown.flag.load(Ordering::Relaxed)
                            || pfds[1].revents & libc::POLLIN != 0
                        {
                            break;
                        }
                        let mut spent = 0usize;
                        while spent < RX_WAKE_CAP {
                            if shutdown.flag.load(Ordering::Relaxed) {
                                break 'outer;
                            }
                            if let Some(peer) = peer {
                                let n = ep.recv_batch(&mut staged, WIRE_DRAIN_BUDGET);
                                spent += n;
                                for slot in &staged[..n] {
                                    if wire_tx
                                        .blocking_send((peer, Bytes::copy_from_slice(slot)))
                                        .is_err()
                                    {
                                        break 'outer;
                                    }
                                }
                                if n == 0 {
                                    break;
                                }
                                if n < staged.len() {
                                    rx_coalesce();
                                }
                            } else {
                                let n = ep.recv_batch_from(
                                    &mut staged,
                                    &mut staged_addrs,
                                    WIRE_DRAIN_BUDGET,
                                );
                                spent += n;
                                for (buf, src) in staged[..n].iter().zip(&staged_addrs[..n]) {
                                    let item = (*src, Bytes::copy_from_slice(buf));
                                    if wire_tx.blocking_send(item).is_err() {
                                        break 'outer;
                                    }
                                }
                                if n == 0 {
                                    break;
                                }
                                if n < staged.len() {
                                    rx_coalesce();
                                }
                            }
                        }
                    }
                    // Thread owns the read end — closing it here means
                    // a later `stop()` write is `EPIPE` (harmless with
                    // `MSG_NOSIGNAL`), never a stale-fd poll.
                    unsafe {
                        libc::close(wake_r);
                    }
                }
            })
            .expect("spawn wg-rx-bridge");
        (RxJoin::Os(join), stop)
    }

    /// RX leg, tokio-task variant — the pre-thread shape, kept for
    /// platforms without `libc` (Windows, *BSD): the same batch drain
    /// parked on `readable().await` instead of `poll(fd)`. Scheduling
    /// starvation can still queue it behind a synchronous actor pass,
    /// so the channel-full backpressure edge is unchanged — this is a
    /// carryover, not a regression.
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    fn spawn_rx(
        ep: &Arc<BatchEndpoint>,
        peer: Option<SocketAddr>,
        wire_tx: mpsc::Sender<(SocketAddr, Bytes)>,
    ) -> (RxJoin, RxStop) {
        let stop = RxStop::new();
        let shutdown = stop.clone();
        let task = tokio::spawn({
            let ep = Arc::clone(ep);
            async move {
                // Both socket shapes batch the kernel drain —
                // `recv_batch` connected, `recv_batch_from`
                // unconnected (the listener's demux keeps every real
                // source) — then one gated `try_recv*` tail clears the
                // cached readiness the raw-fd batch can't touch.
                let mut staged: Vec<Vec<u8>> = (0..WIRE_DRAIN_BUDGET)
                    .map(|_| Vec::with_capacity(BRIDGE_SLOT))
                    .collect();
                let mut staged_addrs: Vec<SocketAddr> =
                    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0); WIRE_DRAIN_BUDGET];
                let mut single = vec![0u8; BRIDGE_BUF];
                'outer: loop {
                    let r = tokio::select! {
                        biased;
                        _ = shutdown.pulse.notified() => break,
                        r = ep.readable() => r,
                    };
                    // A dead fd ends the bridge: dropping `wire_tx`
                    // closes the channel, and the actor's recv sees
                    // `ConnectionReset` — the terminal verdict.
                    if r.is_err() {
                        break;
                    }
                    let mut spent = 0usize;
                    while spent < RX_WAKE_CAP {
                        if let Some(peer) = peer {
                            let n = ep.recv_batch(&mut staged, WIRE_DRAIN_BUDGET);
                            spent += n;
                            for slot in &staged[..n] {
                                if wire_tx
                                    .send((peer, Bytes::copy_from_slice(slot)))
                                    .await
                                    .is_err()
                                {
                                    break 'outer;
                                }
                            }
                            if n < staged.len() {
                                // `recv_batch` drains through the raw
                                // fd, invisible to tokio's readiness
                                // tracking — a short batch means the
                                // kernel queue is dry, so finish with
                                // one gated `try_recv`. It clears the
                                // cached readable bit so the next
                                // `readable()` parks on true kernel
                                // state, delivers a straggler that
                                // landed mid-drain, and surfaces a
                                // persistent socket error as terminal.
                                match ep.try_recv(&mut single) {
                                    Ok(m) => {
                                        spent += 1;
                                        let pkt = Bytes::copy_from_slice(&single[..m]);
                                        if wire_tx.send((peer, pkt)).await.is_err() {
                                            break 'outer;
                                        }
                                        continue;
                                    }
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                    Err(_) => break 'outer,
                                }
                            }
                        } else {
                            let n = ep.recv_batch_from(
                                &mut staged,
                                &mut staged_addrs,
                                WIRE_DRAIN_BUDGET,
                            );
                            spent += n;
                            for (buf, src) in staged[..n].iter().zip(&staged_addrs[..n]) {
                                if wire_tx
                                    .send((*src, Bytes::copy_from_slice(buf)))
                                    .await
                                    .is_err()
                                {
                                    break 'outer;
                                }
                            }
                            if n < staged.len() {
                                match ep.try_recv_from(&mut single) {
                                    Ok((m, src)) => {
                                        spent += 1;
                                        let pkt = Bytes::copy_from_slice(&single[..m]);
                                        if wire_tx.send((src, pkt)).await.is_err() {
                                            break 'outer;
                                        }
                                        continue;
                                    }
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                    Err(_) => break 'outer,
                                }
                            }
                        }
                    }
                }
            }
        });
        (RxJoin::Tokio(task), stop)
    }

    /// See [`BatchEndpoint::try_recv`]: channel `Empty` maps to
    /// `WouldBlock`, `Disconnected` — the RX bridge gone — to
    /// `ConnectionReset`, the terminal verdict the caller already owns.
    pub fn try_recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rx.try_recv() {
            Ok((_src, pkt)) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
    }

    /// [`try_recv`](Self::try_recv) with the datagram's source — the
    /// listener's demux key.
    pub fn try_recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.rx.try_recv() {
            Ok((src, pkt)) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok((n, src))
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
    }

    /// See [`BatchEndpoint::recv`]: the async form awaits the RX
    /// channel instead of the kernel socket — a closed channel (RX
    /// bridge exit) reports `ConnectionReset`.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rx.recv().await {
            Some((_src, pkt)) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::from(io::ErrorKind::ConnectionReset)),
        }
    }

    /// [`recv`](Self::recv) with the datagram's source.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.rx.recv().await {
            Some((src, pkt)) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok((n, src))
            }
            None => Err(io::Error::from(io::ErrorKind::ConnectionReset)),
        }
    }

    /// See [`Endpoint::recv_batch`] / `ProxyEndpoint::recv_batch`:
    /// pops channel datagrams into the staged slots under the same
    /// leading-count contract.
    pub fn recv_batch(&mut self, bufs: &mut [Vec<u8>], budget: usize) -> usize {
        let n = bufs.len().min(budget).min(WIRE_DRAIN_BUDGET);
        let mut got = 0;
        for buf in &mut bufs[..n] {
            match self.rx.try_recv() {
                Ok((_src, pkt)) => {
                    buf.clear();
                    let take = pkt.len().min(buf.capacity());
                    buf.extend_from_slice(&pkt[..take]);
                    got += 1;
                }
                Err(_) => break,
            }
        }
        got
    }

    /// See [`BatchEndpoint::try_send`]. On a connected endpoint the
    /// channel item's `dst` is the bound peer; an unconnected one has
    /// no peer to stamp and reports `NotConnected` like a std socket.
    /// A full channel is `WouldBlock` — the requeue edge
    /// `flush_outbox` already keys on.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        let Some(peer) = self.peer else {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        };
        self.send_one(peer, buf)
    }

    /// See [`BatchEndpoint::try_send_to`]: the channel analogue —
    /// `WouldBlock` on a full queue, `ConnectionReset` when the TX
    /// bridge is gone.
    pub fn try_send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.send_one(addr, buf)
    }

    /// The shared `try_send` core.
    fn send_one(&self, addr: SocketAddr, buf: &[u8]) -> io::Result<usize> {
        match self.tx.try_send((addr, Bytes::copy_from_slice(buf))) {
            Ok(()) => Ok(buf.len()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
    }

    /// See [`BatchEndpoint::send_batch`]: a `try_send` loop returning
    /// the leading accepted count — the channel-full boundary behaves
    /// exactly like the kernel's send stop.
    pub fn send_batch(&self, pkts: &[&[u8]], addr: SocketAddr) -> usize {
        let mut sent = 0;
        for pkt in pkts {
            match self.tx.try_send((addr, Bytes::copy_from_slice(pkt))) {
                Ok(()) => sent += 1,
                Err(_) => break,
            }
        }
        sent
    }

    /// See [`BatchEndpoint::send_batch_to`]: per-datagram destination
    /// rides the channel item; connected semantics ignore it downstream.
    pub fn send_batch_to(&self, pkts: &[(SocketAddr, &[u8])]) -> usize {
        let mut sent = 0;
        for (addr, pkt) in pkts {
            match self.tx.try_send((*addr, Bytes::copy_from_slice(pkt))) {
                Ok(()) => sent += 1,
                Err(_) => break,
            }
        }
        sent
    }

    /// See [`BatchEndpoint::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}

impl Drop for BridgedEndpoint {
    /// The `ProxyEndpoint` contract, extended for the dedicated RX
    /// thread: `rx.close()` errors any `blocking_send` parked on a
    /// full channel (the receiver field can't drop until this `Drop`
    /// returns — the thread would out-wait `join` without this),
    /// `stop()`'s wake byte pulls the thread out of `poll`
    /// immediately, and `join` waits it out so the socket fd is
    /// actually released before teardown returns — the
    /// port-is-free-on-shutdown contract, not a ~50 ms race.
    fn drop(&mut self) {
        self.rx.close();
        self.shutdown_rx.stop();
        self.shutdown_tx.notify_one();
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        if let Some(RxJoin::Os(join)) = self._bridge.0.take() {
            let _ = join.join();
        }
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
///   (`ERESTART`/`EINTR`/`EWOULDBLOCK`/`ENOBUFS` after a
///   partial send return the count, not the errno). `msg_flags` and
///   `msg_datalen` must be zero on input. A connected datagram socket
///   takes the `sendit_x`/`sosend_list` fast path; an unconnected one
///   runs an in-kernel `sendit` loop that honours each message's
///   `msg_name`/`msg_namelen` — the header comment's "address … not
///   supported" is stale relative to the implementation.
/// - `recvmsg_x` returns the count of datagrams received (the first
///   message may block only without `MSG_DONTWAIT` — we always pass
///   it), writing each message's copied byte count into `msg_datalen`.
///   `cnt` is clipped to `kern.ipc.maxrecvmsgx` (sysctl, default 100 —
///   RW and tuneable down; `sendmsg_x` above clips at `maxsendmsgx`
///   the same way) and only `0`/`> UIO_MAXIOV` fails EINVAL outright.
///   Either way the batch just comes back short: the callers'
///   short-count handling re-issues the remainder per datagram, so a
///   tuned-down ceiling degrades the batch without reordering it.
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
    // identical field order/sizes. If any assert trips the binding
    // drifted from the wire format.
    const _: () = assert!(size_of::<msghdr_x>() == 56);
    const _: () = assert!(align_of::<msghdr_x>() == 8);
    const _: () = assert!(std::mem::offset_of!(msghdr_x, msg_iov) == 16);
    const _: () = assert!(std::mem::offset_of!(msghdr_x, msg_control) == 32);
    const _: () = assert!(std::mem::offset_of!(msghdr_x, msg_flags) == 44);
    const _: () = assert!(std::mem::offset_of!(msghdr_x, msg_datalen) == 48);

    // `cnt` ceiling pin: XNU clips each call's datagram count at
    // `somaxsendmsgx`/`somaxrecvmsgx` (default 100 — see the module
    // docs) and EINVALs past `UIO_MAXIOV`. The per-call chunk stays
    // under the default ceiling even though `WIRE_DRAIN_BUDGET` may
    // exceed it — a bigger budget is serviced over several calls,
    // while a chunk sized past the ceiling would silently truncate
    // the tail of every round.
    const _: () = assert!(
        super::BatchEndpoint::MSGX_CHUNK <= 100,
        "MSGX_CHUNK exceeds XNU's default sendmsg_x/recvmsg_x cnt ceiling (100)"
    );

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

/// Decode a `sockaddr_storage` the kernel wrote through `msg_name` —
/// the inverse of `write_sockaddr`. Only family/port/addr are read, so
/// the Darwin `sin_len` byte needs no platform split; an unrecognised
/// family reports the unspecified wildcard, which the demux's table
/// simply finds no peer for — the same verdict a non-peer source gets.
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", not(feature = "no-macos-sendmsg-x"))
))]
fn read_sockaddr(storage: &libc::sockaddr_storage) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: the kernel wrote a `sockaddr_in` — family proved.
            let sa =
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(sa.sin_addr.s_addr.to_be())),
                u16::from_be(sa.sin_port),
            )
        }
        libc::AF_INET6 => {
            // SAFETY: the kernel wrote a `sockaddr_in6` — family proved.
            let sa = unsafe {
                &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)),
                u16::from_be(sa.sin6_port),
            )
        }
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    }
}

#[cfg(test)]
mod tests {
    //! Loopback UDP batch I/O. On Linux these drive the real
    //! `sendmmsg`/`recvmmsg` path, on macOS `sendmsg_x`/`recvmsg_x`
    //! (unless `no-macos-sendmsg-x` put the fallback back), elsewhere
    //! the per-datagram loop.
    use super::*;
    use crate::enlarge_recv_buffer;

    fn std_sock() -> std::net::UdpSocket {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        s.set_nonblocking(true).expect("nonblocking");
        s
    }

    fn ep(s: std::net::UdpSocket, connected: bool) -> BatchEndpoint {
        let t = tokio::net::UdpSocket::from_std(s).expect("tokio socket");
        // Production endpoints enlarge `SO_RCVBUF`; a test socket on
        // the stock ~208 KiB makes every flood assertion a kernel-
        // capacity coin flip instead of a batch-semantics check.
        enlarge_recv_buffer(&t);
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

    /// Chunks past the per-call stack-array bound: a batch wider than
    /// two rounds takes ≥3 mmsg/msgx rounds on Linux/macOS — the
    /// `pkts[sent..sent + n]` offset must stay exact — and a plain
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

        // > 2 × the per-call chunk ⇒ ≥3 kernel rounds on either backend
        // (mmsg chunks at `WIRE_DRAIN_BUDGET`, msgx at `MSGX_CHUNK`).
        // Payloads stay ≤39 B so the queued batch fits a stock kernel
        // receive buffer whole.
        const N: usize = 2 * WIRE_DRAIN_BUDGET + 2;
        let payloads: Vec<Vec<u8>> = (0..N).map(|i| vec![i as u8; 8 + i % 32]).collect();
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

        const N: usize = 2 * WIRE_DRAIN_BUDGET + 2;
        let payloads: Vec<Vec<u8>> = (0..N).map(|i| vec![i as u8; 8 + i % 32]).collect();
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

    // ── ProxyEndpoint bridge tests (issue #899) ────────────────────

    /// A `ProxyPacketConn` over two test-owned mpsc halves: `in_tx`
    /// feeds `read_packet`, `out_rx` collects every `write_packet` with
    /// its stamped address. The trait is `#[async_trait]` but this
    /// crate carries no `async-trait` dep (and must not add one for
    /// tests), so the impl spells out the desugared signature.
    ///
    /// `held` is a write gate — while the test holds its lock every
    /// `write_packet` parks, so fill-count assertions are deterministic
    /// (the bridge consumed exactly the datagrams it provably reported,
    /// no more). `write_started` fires inside `write_packet` so a test
    /// can wait until the bridge is holding a datagram mid-write before
    /// measuring queue depth.
    struct FakeConn {
        inbound: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
        outbound: mpsc::Sender<(Bytes, SocketAddr)>,
        remote: SocketAddr,
        local: SocketAddr,
        held: tokio::sync::Mutex<()>,
        write_started: Notify,
        closed: std::sync::atomic::AtomicBool,
    }

    impl meow_common::ProxyPacketConn for FakeConn {
        fn read_packet<'a, 'b, 'c>(
            &'a self,
            buf: &'b mut [u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = meow_common::Result<(usize, SocketAddr)>>
                    + Send
                    + 'c,
            >,
        >
        where
            'a: 'c,
            'b: 'c,
        {
            Box::pin(async move {
                match self.inbound.lock().await.recv().await {
                    Some(pkt) => {
                        let n = pkt.len().min(buf.len());
                        buf[..n].copy_from_slice(&pkt[..n]);
                        Ok((n, self.remote))
                    }
                    None => Err(meow_common::MeowError::Proxy(
                        "fake conn: inbound closed".into(),
                    )),
                }
            })
        }

        fn write_packet<'a, 'b, 'd, 'c>(
            &'a self,
            buf: &'b [u8],
            addr: &'d SocketAddr,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = meow_common::Result<usize>> + Send + 'c>,
        >
        where
            'a: 'c,
            'b: 'c,
            'd: 'c,
        {
            Box::pin(async move {
                self.write_started.notify_one();
                let _held = self.held.lock().await;
                if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(meow_common::MeowError::Proxy("fake conn: closed".into()));
                }
                self.outbound
                    .send((Bytes::copy_from_slice(buf), *addr))
                    .await
                    .map_err(|_| meow_common::MeowError::Proxy("fake conn: outbox gone".into()))?;
                Ok(buf.len())
            })
        }

        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok(self.local)
        }

        fn close(&self) -> meow_common::Result<()> {
            self.closed
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    /// `FakeConn` plus the halves the test drives: `in_tx` injects
    /// datagrams the conn reads, `out_rx` observes what the TX bridge
    /// writes back.
    struct FakeWire {
        conn: Arc<FakeConn>,
        in_tx: mpsc::Sender<Bytes>,
        out_rx: mpsc::Receiver<(Bytes, SocketAddr)>,
        endpoint: SocketAddr,
        local: SocketAddr,
    }

    fn fake_wire() -> FakeWire {
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(8);
        let (out_tx, out_rx) = mpsc::channel::<(Bytes, SocketAddr)>(PROXY_ENDPOINT_QUEUE + 8);
        let endpoint: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let local: SocketAddr = "192.0.2.4:41000".parse().unwrap();
        FakeWire {
            conn: Arc::new(FakeConn {
                inbound: tokio::sync::Mutex::new(in_rx),
                outbound: out_tx,
                remote: endpoint,
                local,
                held: tokio::sync::Mutex::new(()),
                write_started: Notify::new(),
                closed: std::sync::atomic::AtomicBool::new(false),
            }),
            in_tx,
            out_rx,
            endpoint,
            local,
        }
    }

    impl FakeWire {
        /// The conn as the trait object `ProxyEndpoint::new` takes —
        /// the coercion point keeps call sites to one word.
        #[allow(
            clippy::clone_on_ref_ptr,
            reason = "the Arc<FakeConn> → Arc<dyn ProxyPacketConn> unsize cannot ride Arc::clone(&_) — its generic T is pinned by the argument's concrete type"
        )]
        fn proxy_conn(&self) -> Arc<dyn meow_common::ProxyPacketConn> {
            self.conn.clone()
        }
    }

    /// `Endpoint::try_recv` on a `Proxy` picks up what the front conn
    /// delivered: RX bridge → queue → pump slot.
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_rx_delivers_to_pump() {
        let w = fake_wire();
        let mut ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));
        w.in_tx.send(Bytes::from_static(b"wg-init")).await.unwrap();

        let mut buf = vec![0u8; 128];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match ep.try_recv(&mut buf) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(e) => panic!("unexpected recv error: {e}"),
                }
            }
        })
        .await
        .expect("bridge must deliver within 5s");
        assert_eq!(&buf[..n], b"wg-init");
        assert_eq!(ep.local_addr().unwrap(), w.local);
    }

    /// `try_send` → TX bridge → `write_packet` on the conn, with the
    /// construction-time endpoint address stamped on every datagram.
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_tx_delivers_to_conn() {
        let w = fake_wire();
        let mut w = w;
        let ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));

        ep.try_send(b"wg-data").expect("try_send");
        let (pkt, addr) = tokio::time::timeout(std::time::Duration::from_secs(5), w.out_rx.recv())
            .await
            .expect("TX bridge delivers")
            .expect("outbox open");
        assert_eq!(&pkt[..], b"wg-data");
        assert_eq!(addr, w.endpoint, "stamps the bound endpoint address");
    }

    /// A dead conn (read errors) disconnects the RX queue — the pump's
    /// `recv` then surfaces `ConnectionReset`, its dead-endpoint signal.
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_conn_dead_signals_disconnect() {
        let w = fake_wire();
        let mut ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));
        // Drop the injection half: the fake's read_packet errors, the RX
        // bridge exits, its queue sender drops.
        drop(w.in_tx);

        let mut buf = vec![0u8; 64];
        let err = tokio::time::timeout(std::time::Duration::from_secs(5), ep.recv(&mut buf))
            .await
            .expect("disconnect surfaces within 5s")
            .expect_err("closed queue reads as an error");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    /// A full TX queue reports `WouldBlock` — the signal the pump's
    /// `flush_outbox` treats like socket `EAGAIN` (requeue and stop).
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_send_full_returns_would_block() {
        let w = fake_wire();
        let gate = w.conn.held.lock().await; // park every write_packet
        let ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));
        // One datagram to prime the bridge: the await below returns once
        // the bridge is parked mid-write holding it, so the queue is
        // provably empty from here on.
        ep.try_send(b"held").expect("first send");
        w.conn.write_started.notified().await;
        for _ in 0..PROXY_ENDPOINT_QUEUE {
            ep.try_send(b"x").expect("queue accepts up to capacity");
        }
        let err = ep.try_send(b"overflow").expect_err("full queue");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(gate);
    }

    /// Dropping the endpoint unwinds both bridges: the RX task's
    /// `Notify` arm fires, the TX task drains the closed queue and calls
    /// `conn.close()`.
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_drop_shuts_down_bridge() {
        let w = fake_wire();
        let conn = Arc::clone(&w.conn);
        let ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));
        drop(ep);

        let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !conn.closed.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        })
        .await;
        closed.expect("TX bridge must close the conn after endpoint drop");
    }

    /// `recv_batch` honours the budget: a queue deeper than `budget`
    /// drains exactly `budget` datagrams, in order.
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_recv_batch_drains_up_to_budget() {
        let w = fake_wire();
        let mut ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));
        const N: usize = 6;
        for i in 0..N {
            w.in_tx.send(Bytes::from(vec![i as u8; 16])).await.unwrap();
        }
        // Let the bridge top the queue up before the batch is measured.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut bufs: Vec<Vec<u8>> = (0..N).map(|_| vec![0u8; 64]).collect();
        let got = ep.recv_batch(&mut bufs, 3);
        assert_eq!(got, 3, "budget clamps the drain");
        for (i, buf) in bufs[..got].iter().enumerate() {
            assert_eq!(buf.as_slice(), &[i as u8; 16], "wire order preserved");
        }
    }

    /// `send_batch` returns the leading accepted count and stops at a
    /// full queue — the same short-count contract `sendmmsg` gives —
    /// then unblocking the conn lets the bridge drain the queue in
    /// order with the stamped address on every datagram.
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_send_batch_stops_on_full() {
        let mut w = fake_wire();
        let gate = w.conn.held.lock().await; // park every write_packet
        let ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));
        ep.try_send(b"first").expect("first send");
        w.conn.write_started.notified().await; // bridge parked on pkt 1
        for _ in 0..PROXY_ENDPOINT_QUEUE {
            ep.try_send(b"x").expect("queue accepts up to capacity");
        }
        let pkts: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let sent = ep.send_batch(&pkts, w.endpoint);
        assert_eq!(sent, 0, "a full queue reports a zero accepted count");

        drop(gate);
        // The bridge drains in order: the in-flight "first" write, then
        // the queued datagrams — every one stamped with the endpoint.
        let (pkt, addr) = tokio::time::timeout(std::time::Duration::from_secs(5), w.out_rx.recv())
            .await
            .expect("TX bridge drains after unblock")
            .expect("outbox open");
        assert_eq!(&pkt[..], b"first");
        assert_eq!(addr, w.endpoint);
    }

    /// Dropping the endpoint interrupts a *stalled* write too: the TX
    /// task's own `Notify` edge cancels the parked `write_packet`
    /// (the `pump_rx` close alone cannot reach into an in-flight
    /// write), so the task exits through `conn.close()` while the
    /// front hop is still wedged. `FakeConn` with `held` taken is the
    /// spec's `SlowConn` — the write would outlive any timeout the
    /// test could wait out, so only the drop edge can free the task.
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_drop_interrupts_stalled_write() {
        let w = fake_wire();
        let conn = Arc::clone(&w.conn);
        let gate = w.conn.held.lock().await; // every write_packet parks
        let ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));
        ep.try_send(b"stalled").expect("try_send");
        // The bridge is now provably parked inside `write_packet`.
        w.conn.write_started.notified().await;

        drop(ep); // pulses both drop edges, then `pump_tx` closes

        // The gate stays held — the write never returns — yet the TX
        // task must still complete, and its only exit path runs
        // `conn.close()`. Without the shutdown select arm this would
        // hang until `PROXY_WRITE_TIMEOUT` (30 s) at best.
        let closed = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            while !conn.closed.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        })
        .await;
        drop(gate);
        closed.expect("TX bridge must close the conn within 500ms of drop");
    }

    /// A `write_packet` that returns `Err` is terminal for the front
    /// conn — the TX task exits and closes it rather than draining the
    /// queue into a dead hop.
    #[tokio::test(flavor = "current_thread")]
    async fn proxy_endpoint_tx_write_error_closes_conn() {
        let w = fake_wire();
        let conn = Arc::clone(&w.conn);
        conn.closed
            .store(true, std::sync::atomic::Ordering::Relaxed); // next write errs
        let ep = Endpoint::Proxy(ProxyEndpoint::new(w.proxy_conn(), w.endpoint, w.local));
        ep.try_send(b"lost").expect("try_send");

        // The write error itself is what breaks the loop — `closed`
        // was already true, so a still-running task would leave it
        // unchanged; instead assert the task drained out and the
        // queue closed: a second try_send must see the dead channel.
        let dead = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match ep.try_send(b"probe") {
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
                    _ => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        dead.expect("TX bridge must exit on write error within 5s");
    }

    // ── P1 regression: TX death must take the RX bridge with it ──
    //
    // The defect the `NotifyOnDrop` guard fixes: a TX task exiting on
    // a write error or `PROXY_WRITE_TIMEOUT` only called `conn.close()`
    // — a no-op on the Raw `ProxyPacketConn`s — so the RX task's parked
    // `read_packet` never noticed, `wire_tx` never dropped, and the
    // pump's `recv` never saw `ConnectionReset`. Both conns below share
    // the Raw shape: parked read, no-op close, writes that die in
    // different ways.

    /// `write_packet` errs `delay` in — the front hop dying mid-write —
    /// while `read_packet` parks forever and `close()` is a no-op: the
    /// exact conn shape whose `close()` could not interrupt the RX
    /// bridge's parked read in the P1 defect.
    struct DelayedErrConn {
        delay: Duration,
        local: SocketAddr,
    }

    impl meow_common::ProxyPacketConn for DelayedErrConn {
        fn read_packet<'a, 'b, 'c>(
            &'a self,
            _buf: &'b mut [u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = meow_common::Result<(usize, SocketAddr)>>
                    + Send
                    + 'c,
            >,
        >
        where
            'a: 'c,
            'b: 'c,
        {
            Box::pin(async move {
                std::future::pending::<meow_common::Result<(usize, SocketAddr)>>().await
            })
        }

        fn write_packet<'a, 'b, 'd, 'c>(
            &'a self,
            _buf: &'b [u8],
            _addr: &'d SocketAddr,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = meow_common::Result<usize>> + Send + 'c>,
        >
        where
            'a: 'c,
            'b: 'c,
            'd: 'c,
        {
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                Err(meow_common::MeowError::Io(io::Error::from(
                    io::ErrorKind::ConnectionReset,
                )))
            })
        }

        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok(self.local)
        }

        fn close(&self) -> meow_common::Result<()> {
            Ok(()) // no-op — the Raw-conn shape under test
        }
    }

    /// The wedged-write shape: `write_packet` parks forever (a
    /// flow-controlled or half-dead transport) so only
    /// `PROXY_WRITE_TIMEOUT` can end it; `write_started` lets a test
    /// prove the TX bridge is mid-write before the clock is advanced
    /// past the bound.
    struct HangConn {
        write_started: Notify,
        local: SocketAddr,
    }

    impl meow_common::ProxyPacketConn for HangConn {
        fn read_packet<'a, 'b, 'c>(
            &'a self,
            _buf: &'b mut [u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = meow_common::Result<(usize, SocketAddr)>>
                    + Send
                    + 'c,
            >,
        >
        where
            'a: 'c,
            'b: 'c,
        {
            Box::pin(async move {
                std::future::pending::<meow_common::Result<(usize, SocketAddr)>>().await
            })
        }

        fn write_packet<'a, 'b, 'd, 'c>(
            &'a self,
            _buf: &'b [u8],
            _addr: &'d SocketAddr,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = meow_common::Result<usize>> + Send + 'c>,
        >
        where
            'a: 'c,
            'b: 'c,
            'd: 'c,
        {
            Box::pin(async move {
                self.write_started.notify_one();
                std::future::pending::<meow_common::Result<usize>>().await
            })
        }

        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok(self.local)
        }

        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }

    /// A dead TX write must take the RX bridge down with it: the
    /// `NotifyOnDrop` guard pulses `shutdown_rx` on the TX task's exit,
    /// so `recv` surfaces `ConnectionReset` well inside 500 ms rather
    /// than parking on a `read_packet` that can never report again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_endpoint_tx_write_error_stops_rx_bridge() {
        let conn = Arc::new(DelayedErrConn {
            delay: Duration::from_millis(50),
            local: "192.0.2.4:41000".parse().unwrap(),
        });
        let mut ep = Endpoint::Proxy(ProxyEndpoint::new(
            conn,
            "203.0.113.7:51820".parse().unwrap(),
            "192.0.2.4:41000".parse().unwrap(),
        ));
        ep.try_send(b"trigger").expect("try_send");

        let mut buf = vec![0u8; 64];
        let err = tokio::time::timeout(Duration::from_millis(500), ep.recv(&mut buf))
            .await
            .expect("RX bridge must exit within 500 ms of TX death — P1 regression")
            .expect_err("a dead front conn reads as ConnectionReset");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    /// The timeout arm of the same chain: a write parked past
    /// `PROXY_WRITE_TIMEOUT` exits the TX task, and the guard must
    /// pulse `shutdown_rx` there too. `start_paused` fast-forwards the
    /// 30 s bound — the bridge's own write timeout fires, then the RX
    /// bridge follows it out and `recv` reports `ConnectionReset`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn proxy_endpoint_tx_write_timeout_stops_rx_bridge() {
        let conn = Arc::new(HangConn {
            write_started: Notify::new(),
            local: "192.0.2.4:41000".parse().unwrap(),
        });
        let write_started = Arc::clone(&conn);
        let mut ep = Endpoint::Proxy(ProxyEndpoint::new(
            conn,
            "203.0.113.7:51820".parse().unwrap(),
            "192.0.2.4:41000".parse().unwrap(),
        ));
        ep.try_send(b"stalled").expect("try_send");
        // Provably mid-write before the clock moves.
        write_started.write_started.notified().await;

        tokio::time::advance(PROXY_WRITE_TIMEOUT + Duration::from_secs(1)).await;

        let mut buf = vec![0u8; 64];
        let err = tokio::time::timeout(Duration::from_secs(5), ep.recv(&mut buf))
            .await
            .expect("RX bridge must exit after TX write timeout — P1 regression")
            .expect_err("a dead front conn reads as ConnectionReset");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    // ── BridgedEndpoint: the kernel socket behind the same bridge ──
    //
    // These pin the contract both owners rely on — the pump's
    // `Endpoint::Batch` and the listener's actor: FIFO wire order, the
    // unconnected path's per-datagram source, channel backpressure as
    // `WouldBlock`, per-datagram kernel-error drop, and bridge exit as
    // `ConnectionReset`.

    /// Build a connected `BridgedEndpoint` whose peer is a plain std
    /// socket; returns the endpoint and the raw peer socket — it
    /// `send_to`s the endpoint's `local_addr` to drive RX.
    fn bridged_pair() -> (BridgedEndpoint, std::net::UdpSocket) {
        let receiver = std_sock();
        let peer = receiver.local_addr().expect("receiver addr");
        let sender = std_sock();
        sender.connect(peer).expect("connect");
        let sock = tokio::net::UdpSocket::from_std(sender).expect("tokio socket");
        // Same as `ep()`: the bridge's drain socket needs production
        // headroom or a burst past `RX_WAKE_CAP` lands-or-drops on the
        // runner's ambient `rmem` tuning, not on bridge semantics.
        enlarge_recv_buffer(&sock);
        (BridgedEndpoint::connected(sock, peer), receiver)
    }

    /// Read `expected` datagrams off a peer socket the bridge sends
    /// toward, in wire order. The `try_clone` rides a tokio socket so
    /// the test task yields at `readable()` — under `current_thread`
    /// the TX bridge runs only at await points.
    async fn drain_peer(receiver: &std::net::UdpSocket, expected: usize) -> Vec<Vec<u8>> {
        let t = tokio::net::UdpSocket::from_std(receiver.try_clone().expect("clone"))
            .expect("tokio receiver");
        let mut got = Vec::new();
        let mut buf = vec![0u8; 65536];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while got.len() < expected {
            match tokio::time::timeout_at(deadline, t.readable()).await {
                Ok(r) => r.expect("readable"),
                Err(_) => break,
            }
            while let Ok(n) = t.try_recv(&mut buf) {
                got.push(buf[..n].to_vec());
            }
        }
        got
    }

    /// Connected RX: a sender burst crosses the bridge into `recv`,
    /// every datagram in wire order.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_connected_rx_fifo() {
        let (mut ep, receiver) = bridged_pair();
        let ep_addr = ep.local_addr().expect("endpoint addr");
        const N: usize = 32;
        let payloads: Vec<Vec<u8>> = (0..N).map(|i| vec![i as u8; 48 + i]).collect();
        for p in &payloads {
            receiver.send_to(p, ep_addr).expect("send");
        }

        let mut buf = vec![0u8; 2048];
        for (i, want) in payloads.iter().enumerate() {
            let n = tokio::time::timeout(Duration::from_secs(5), ep.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("datagram {i} never crossed the RX bridge"))
                .expect("recv");
            assert_eq!(&buf[..n], want.as_slice(), "datagram {i} in wire order");
        }
    }

    /// A flood far past `RX_WAKE_CAP` still arrives complete — the cap
    /// bounds one wake's drain, not the stream: each re-armed
    /// `readable()` continues where the last left off.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridged_rx_burst_past_wake_cap() {
        let (mut ep, receiver) = bridged_pair();
        let ep_addr = ep.local_addr().expect("endpoint addr");
        let n = 3 * RX_WAKE_CAP;
        let payload = vec![0xABu8; 96];
        let send_payload = payload.clone();
        let receiver_thread = std::thread::spawn(move || {
            for _ in 0..n {
                receiver.send_to(&send_payload, ep_addr).expect("send");
            }
        });

        let mut buf = vec![0u8; 2048];
        let mut got = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while got < n {
            match tokio::time::timeout_at(deadline, ep.recv(&mut buf)).await {
                Ok(Ok(m)) => {
                    assert_eq!(&buf[..m], payload.as_slice());
                    got += 1;
                }
                Ok(Err(e)) => panic!("recv: {e}"),
                Err(_) => panic!("RX bridge stalled at {got}/{n}"),
            }
        }
        receiver_thread.join().expect("sender thread");
    }

    /// Unconnected RX preserves each datagram's real source — the
    /// listener demux keys on it. Two senders interleave; `recv_from`
    /// must report the right one per datagram.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_unconnected_recv_from_preserves_src() {
        let ep_sock = std_sock();
        let ep_addr = ep_sock.local_addr().expect("addr");
        let sock = tokio::net::UdpSocket::from_std(ep_sock).expect("tokio socket");
        let mut ep = BridgedEndpoint::unconnected(sock);

        let a = std_sock();
        let a_addr = a.local_addr().expect("a addr");
        let b = std_sock();
        let b_addr = b.local_addr().expect("b addr");
        a.send_to(b"from-a", ep_addr).expect("a send");
        b.send_to(b"from-b", ep_addr).expect("b send");
        a.send_to(b"from-a-2", ep_addr).expect("a send 2");

        let mut seen: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut buf = vec![0u8; 256];
        for _ in 0..3 {
            let (n, src) = tokio::time::timeout(Duration::from_secs(5), ep.recv_from(&mut buf))
                .await
                .expect("datagram never crossed the RX bridge")
                .expect("recv_from");
            seen.push((src, buf[..n].to_vec()));
        }
        seen.sort_by_key(|(s, _)| *s);
        let mut want = vec![
            (a_addr, b"from-a".to_vec()),
            (a_addr, b"from-a-2".to_vec()),
            (b_addr, b"from-b".to_vec()),
        ];
        want.sort_by_key(|(s, _)| *s);
        assert_eq!(seen, want, "each datagram keeps its real source");
    }

    /// Unconnected TX routes each channel item to its stamped
    /// destination — `try_send_to` reaches two different receivers.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_unconnected_send_to_routes_per_peer() {
        let ep_sock = std_sock();
        let sock = tokio::net::UdpSocket::from_std(ep_sock).expect("tokio socket");
        let ep = BridgedEndpoint::unconnected(sock);

        let a = std_sock();
        let a_addr = a.local_addr().expect("a addr");
        let b = std_sock();
        let b_addr = b.local_addr().expect("b addr");

        ep.try_send_to(b"to-a", a_addr).expect("try_send_to a");
        ep.try_send_to(b"to-b", b_addr).expect("try_send_to b");

        assert_eq!(drain_peer(&a, 1).await, vec![b"to-a".to_vec()]);
        assert_eq!(drain_peer(&b, 1).await, vec![b"to-b".to_vec()]);
    }

    /// `try_send` on an unconnected endpoint has no peer to stamp —
    /// `NotConnected`, the std-socket verdict.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_unconnected_try_send_is_not_connected() {
        let ep_sock = std_sock();
        let sock = tokio::net::UdpSocket::from_std(ep_sock).expect("tokio socket");
        let ep = BridgedEndpoint::unconnected(sock);
        let err = ep.try_send(b"nowhere").expect_err("unconnected try_send");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    /// A full TX channel reports `WouldBlock` — the requeue boundary
    /// `flush_outbox` keys on. `current_thread` never yields between
    /// sends, so the queue fills at exactly `PROXY_ENDPOINT_QUEUE`.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_try_send_full_channel_is_wouldblock() {
        let (ep, _receiver) = bridged_pair();
        for i in 0..PROXY_ENDPOINT_QUEUE {
            ep.try_send(&[i as u8; 16])
                .unwrap_or_else(|e| panic!("queue slot {i}: {e}"));
        }
        let err = ep
            .try_send(b"one too many")
            .expect_err("a full channel is WouldBlock");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bridged_tx_sends_single_datagram_without_timer() {
        let (ep, receiver) = bridged_pair();
        receiver.set_nonblocking(false).expect("blocking receiver");
        // Give the receive a real deadline so it does not move the
        // virtual clock used to detect a delay in the TX bridge.
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("receive deadline");
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let mut buf = [0; 16];
            let received = receiver.recv(&mut buf).map(|n| (buf, n));
            let _ = tx.send(received);
        });

        let start = tokio::time::Instant::now();
        ep.try_send(b"sparse").expect("enqueue datagram");
        let (buf, n) = rx.await.expect("receiver thread").expect("datagram");
        assert_eq!(&buf[..n], b"sparse");
        assert_eq!(tokio::time::Instant::now(), start);
    }

    /// A kernel send error drops only the offending datagram: an
    /// oversized payload hits `EMSGSIZE` in the TX bridge and the
    /// queued datagram behind it still reaches the wire.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_tx_oversized_drops_only_that_datagram() {
        let (ep, receiver) = bridged_pair();
        let oversized = vec![0xEEu8; 70000];
        ep.try_send(&oversized).expect("oversized enqueues");
        ep.try_send(b"survivor").expect("survivor enqueues");

        let got = drain_peer(&receiver, 1).await;
        assert_eq!(
            got,
            vec![b"survivor".to_vec()],
            "EMSGSIZE drops just itself"
        );
    }

    /// RX bridge exit closes the channel: `recv` reports
    /// `ConnectionReset`, the terminal verdict the pump's error arm
    /// stops on. The `shutdown_rx` flag is what `Drop` sets.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_rx_bridge_exit_is_connection_reset() {
        let (mut ep, _receiver) = bridged_pair();
        ep.shutdown_rx.stop();
        let mut buf = vec![0u8; 64];
        let err = tokio::time::timeout(Duration::from_secs(5), ep.recv(&mut buf))
            .await
            .expect("RX bridge must exit on its shutdown edge")
            .expect_err("a dead RX bridge reads as ConnectionReset");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        // `try_recv` sees the same verdict on the closed channel.
        let err = ep.try_recv(&mut buf).expect_err("try_recv");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    /// TX bridge exit closes the send channel: `try_send` reports
    /// `ConnectionReset` rather than queueing into the void.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_tx_bridge_exit_is_connection_reset() {
        let (ep, _receiver) = bridged_pair();
        ep.shutdown_tx.notify_one();
        let dead = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match ep.try_send(b"probe") {
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
                    _ => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        dead.expect("TX bridge must exit on its shutdown edge");
    }

    /// Dropping the endpoint pulses both edges: the RX flag reads set
    /// the moment `drop` returns, and a `notify_one` stores its TX
    /// permit when nothing waits, so `notified()` armed after `drop`
    /// resolves only if `Drop` actually fired the edge — a task
    /// parked on `writable()`/`recv()` unwinds the same way.
    #[tokio::test(flavor = "current_thread")]
    async fn bridged_drop_pulses_both_edges() {
        let (ep, _receiver) = bridged_pair();
        let shutdown_rx = ep.shutdown_rx.clone();
        let shutdown_tx = Arc::clone(&ep.shutdown_tx);
        drop(ep);
        assert!(
            shutdown_rx.flag.load(Ordering::Relaxed),
            "drop must flag the rx edge"
        );
        tokio::time::timeout(Duration::from_secs(5), shutdown_tx.notified())
            .await
            .expect("drop must pulse the tx edge");
    }
}
