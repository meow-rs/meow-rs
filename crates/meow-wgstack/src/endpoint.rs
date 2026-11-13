//! Batched datagram I/O for the WireGuard endpoint socket.
//!
//! [`BatchEndpoint`] wraps the `tokio::net::UdpSocket` both WireGuard
//! actors open toward their peers with batch calls that collapse a
//! wire burst into a single `recvmmsg`/`sendmmsg` syscall on Linux.
//! Everywhere else the same calls degrade to a per-datagram `try_*`
//! loop — BSD/macOS have no mmsg syscalls, and bionic (Android, a
//! separate `target_os`) does not expose the libc wrappers — so the
//! calling actors keep one code path and the syscall savings are
//! strictly an optimization. The ordinary `try_*`/`recv*` methods are
//! forwarded for the single-datagram paths that remain.
//!
//! Batch semantics match the per-packet loops they replace: a short
//! count means the next datagram is the boundary the kernel stopped
//! at — `sendmmsg` folds a post-partial error into the returned
//! count, so re-issuing that datagram with `try_send`/`try_send_to`
//! is how the caller learns `WouldBlock` (requeue) from a real errno
//! (log and drop, then continue).

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

    /// Drain up to `min(bufs.len(), budget)` datagrams — one
    /// `recvmmsg` on Linux, a `try_recv_buf` loop elsewhere. Every
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
        #[cfg(not(target_os = "linux"))]
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

    /// Linux: `sendmmsg` over stack-built `mmsghdr`/`iovec` arrays.
    /// Elsewhere: a `try_send`/`try_send_to` loop that stops at the
    /// first error — the same short-count contract either way.
    #[cfg(not(target_os = "linux"))]
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
            // that outlives this call and whose names point at `sas`.
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

#[cfg(test)]
mod tests {
    //! Loopback UDP batch I/O. This host is macOS, so these exercise
    //! the per-datagram fallback; on Linux the same tests drive the
    //! real `sendmmsg`/`recvmmsg` path.
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

        b.readable().await.expect("receiver readable");
        let mut buf = [0u8; 256];
        let mut got = 0;
        while let Ok(n) = b.try_recv(&mut buf) {
            assert_eq!(&buf[..n], &payloads[got][..]);
            got += 1;
        }
        assert_eq!(got, N);
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

        b.readable().await.expect("receiver readable");
        let mut buf = [0u8; 256];
        let mut got = 0;
        while let Ok(n) = b.try_recv(&mut buf) {
            assert_eq!(&buf[..n], &payloads[got][..]);
            got += 1;
        }
        assert_eq!(got, N);
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
        // Loopback delivery is synchronous at the kernel level; the
        // `readable` await only covers the reactor's readiness cache.
        b.readable().await.expect("readable");
        let n = b.recv_batch(&mut bufs, 10);
        assert_eq!(n, N);
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
        // readiness — re-arm it before the second batch.
        b.readable().await.expect("readable");
        let n = b.recv_batch(&mut bufs, 3);
        assert_eq!(n, 3, "budget clamps the drain");
    }
}
