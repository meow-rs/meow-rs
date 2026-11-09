//! Outbound-socket protector hook for Android `VpnService.protect(fd)`.
//!
//! When `anytls-rs` runs *inside* an Android VPN app, every outbound socket
//! it opens must bypass the VPN itself — otherwise packets to the AnyTLS
//! server (and the per-stream UDP relay) loop back into the tunnel and
//! deadlock. Android exposes a per-fd hook for this:
//! `android.net.VpnService.protect(int fd)`. This module is the single
//! place a host VPN can install that hook; the client-side dial sites in
//! [`crate::client`] go through [`connect_tcp`] / [`bind_udp`], which
//! call the installed protector before `connect()` / `bind()` so the very
//! first SYN / UDP datagram already bypasses the tunnel.
//!
//! The protector trait and global setter are compiled only on Android. On
//! every other target [`connect_tcp`] / [`bind_udp`] degrade to the same
//! plain tokio code path used historically — so call sites need no `cfg`
//! guards.

use std::io;

use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};

#[cfg(any(target_os = "android", target_env = "ohos"))]
mod android {
    use super::*;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::{Arc, RwLock};

    /// Hook invoked on every outbound socket fd just before `connect()` /
    /// `bind()`. Typically a thin JNI shim around
    /// `android.net.VpnService.protect(int)`.
    ///
    /// Implementations must not block — the call runs on the async runtime
    /// worker that is dialing the socket.
    pub trait SocketProtector: Send + Sync {
        /// Protect `fd`. Returning `Err` aborts the connect/bind and the
        /// error propagates back to the caller.
        fn protect(&self, fd: RawFd) -> io::Result<()>;
    }

    static PROTECTOR: RwLock<Option<Arc<dyn SocketProtector>>> = RwLock::new(None);

    /// Install the global socket protector. Call once during VPN startup,
    /// before any AnyTLS client dials.
    ///
    /// Re-installing is allowed (e.g. VPN tear-down / re-create); the new
    /// protector takes effect on the next outbound socket.
    pub fn set_socket_protector(protector: Arc<dyn SocketProtector>) {
        if let Ok(mut guard) = PROTECTOR.write() {
            *guard = Some(protector);
        }
    }

    /// Remove the currently installed protector, if any.
    pub fn clear_socket_protector() {
        if let Ok(mut guard) = PROTECTOR.write() {
            *guard = None;
        }
    }

    /// Snapshot of the currently-installed protector.
    pub fn socket_protector() -> Option<Arc<dyn SocketProtector>> {
        PROTECTOR.read().ok().and_then(|g| g.clone())
    }

    pub(super) async fn connect_tcp_protected(
        dest: SocketAddr,
        protector: &dyn SocketProtector,
    ) -> io::Result<TcpStream> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if dest.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        protector.protect(socket.as_raw_fd())?;
        socket.set_nonblocking(true)?;

        match socket.connect(&dest.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)?;
        stream.writable().await?;
        if let Some(err) = stream.take_error()? {
            return Err(err);
        }
        Ok(stream)
    }

    pub(super) fn bind_udp_protected(
        local: SocketAddr,
        protector: &dyn SocketProtector,
    ) -> io::Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        protector.protect(socket.as_raw_fd())?;
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;

        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
    }
}

#[cfg(any(target_os = "android", target_env = "ohos"))]
pub use android::{
    SocketProtector, clear_socket_protector, set_socket_protector, socket_protector,
};

/// Dial an outbound TCP stream. On Android, applies the installed
/// `SocketProtector` (if any) to the socket fd before `connect()` so the
/// connection bypasses the VPN. On every other target this is equivalent to
/// [`TcpStream::connect`].
///
/// Accepts the same address forms as [`TcpStream::connect`]. When the
/// Android protector path is taken, addresses are resolved first via
/// `tokio::net::lookup_host` and each resolved `SocketAddr` is tried in
/// turn.
pub async fn connect_tcp<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
    #[cfg(any(target_os = "android", target_env = "ohos"))]
    {
        if let Some(p) = android::socket_protector() {
            let mut last_err: Option<io::Error> = None;
            let mut any = false;
            for resolved in tokio::net::lookup_host(addr).await? {
                any = true;
                match android::connect_tcp_protected(resolved, p.as_ref()).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last_err = Some(e),
                }
            }
            return Err(last_err.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    if any {
                        "connect_tcp: all candidates failed"
                    } else {
                        "connect_tcp: no addresses resolved"
                    },
                )
            }));
        }
    }
    TcpStream::connect(addr).await
}

/// Bind an outbound UDP socket. On Android, applies the installed
/// `SocketProtector` (if any) to the socket fd before `bind()`. On every
/// other target this is equivalent to [`UdpSocket::bind`].
pub async fn bind_udp<A: ToSocketAddrs>(local: A) -> io::Result<UdpSocket> {
    #[cfg(any(target_os = "android", target_env = "ohos"))]
    {
        if let Some(p) = android::socket_protector() {
            let resolved = tokio::net::lookup_host(local)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bind_udp: no address resolved")
                })?;
            return android::bind_udp_protected(resolved, p.as_ref());
        }
    }
    UdpSocket::bind(local).await
}

/// Pluggable outbound TCP dialer hook.
///
/// [`connect_tcp`] resolves hostnames with `tokio::net::lookup_host`, i.e.
/// the operating-system resolver. When `anytls-rs` runs inside a VPN app
/// that is itself the system's DNS handler (meow-rs on Android answers the
/// TUN's DNS with an in-process fake-IP server), that resolver hands back
/// fake IPs — so the (correctly protected) socket dials a blackhole and
/// times out. The host app installs a dialer here that resolves through its
/// own real-IP resolver stack (e.g. meow-common's `connect_tcp_host`); when
/// present it fully replaces the resolve+connect path, protector included.
pub trait TcpDialer: Send + Sync {
    /// Dial `host:port` and return a connected stream. `host` may be a
    /// hostname or an IP literal.
    fn dial<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<TcpStream>> + Send + 'a>>;
}

static TCP_DIALER: std::sync::RwLock<Option<std::sync::Arc<dyn TcpDialer>>> =
    std::sync::RwLock::new(None);

/// Install the global TCP dialer. Call once during app startup, before any
/// AnyTLS client dials. Re-installing is allowed; the new dialer takes
/// effect on the next outbound connection.
pub fn set_tcp_dialer(dialer: std::sync::Arc<dyn TcpDialer>) {
    if let Ok(mut guard) = TCP_DIALER.write() {
        *guard = Some(dialer);
    }
}

/// Remove the currently installed dialer, if any.
pub fn clear_tcp_dialer() {
    if let Ok(mut guard) = TCP_DIALER.write() {
        *guard = None;
    }
}

/// Snapshot of the currently-installed dialer.
pub fn tcp_dialer() -> Option<std::sync::Arc<dyn TcpDialer>> {
    TCP_DIALER.read().ok().and_then(|g| g.clone())
}

/// Split a `host:port` / `[v6]:port` address string.
fn split_host_port(addr: &str) -> Option<(&str, u16)> {
    let (host, port) = addr.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some((host, port))
    }
}

/// Dial a `host:port` address string, preferring the installed [`TcpDialer`]
/// and falling back to [`connect_tcp`] (system resolver + optional
/// protector) when none is installed or the address doesn't split.
pub async fn connect_tcp_addr(addr: &str) -> io::Result<TcpStream> {
    if let (Some(dialer), Some((host, port))) = (tcp_dialer(), split_host_port(addr)) {
        return dialer.dial(host, port).await;
    }
    connect_tcp(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_forms() {
        assert_eq!(
            split_host_port("example.com:443"),
            Some(("example.com", 443))
        );
        assert_eq!(split_host_port("1.2.3.4:80"), Some(("1.2.3.4", 80)));
        assert_eq!(split_host_port("[::1]:8443"), Some(("::1", 8443)));
        assert_eq!(split_host_port("no-port"), None);
        assert_eq!(split_host_port(":443"), None);
        assert_eq!(split_host_port("host:notaport"), None);
    }

    #[test]
    fn dialer_registry_roundtrip() {
        struct Nop;
        impl TcpDialer for Nop {
            fn dial<'a>(
                &'a self,
                _host: &'a str,
                _port: u16,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = io::Result<TcpStream>> + Send + 'a>,
            > {
                Box::pin(async { Err(io::Error::other("nop")) })
            }
        }
        clear_tcp_dialer();
        assert!(tcp_dialer().is_none());
        set_tcp_dialer(std::sync::Arc::new(Nop));
        assert!(tcp_dialer().is_some());
        clear_tcp_dialer();
        assert!(tcp_dialer().is_none());
    }
}
