use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Per-connection timeout: a proxy whose dial path stalls (e.g. a
/// handshake that never completes) must surface as an error instead of
/// wedging the harness forever.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Minimal SOCKS5 CONNECT client. Returns a stream tunneled to `target` via `proxy`.
pub async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let mut stream = TcpStream::connect(proxy).await?;
        // Keep the load generator from adding Nagle/delayed-ACK stalls to the
        // proxy measurement, including immediately after the SOCKS handshake.
        stream.set_nodelay(true)?;

        // Auth negotiation: version 5, 1 method, no-auth (0x00)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf[0] != 0x05 || buf[1] != 0x00 {
            return Err(std::io::Error::other(format!(
                "SOCKS5 auth failed: {:02x} {:02x}",
                buf[0], buf[1]
            )));
        }

        // CONNECT request
        match target {
            SocketAddr::V4(addr) => {
                let mut req = [0u8; 10];
                req[0] = 0x05; // version
                req[1] = 0x01; // CONNECT
                req[2] = 0x00; // reserved
                req[3] = 0x01; // IPv4
                req[4..8].copy_from_slice(&addr.ip().octets());
                req[8..10].copy_from_slice(&addr.port().to_be_bytes());
                stream.write_all(&req).await?;
            }
            SocketAddr::V6(addr) => {
                let mut req = [0u8; 22];
                req[0] = 0x05;
                req[1] = 0x01;
                req[2] = 0x00;
                req[3] = 0x04; // IPv6
                req[4..20].copy_from_slice(&addr.ip().octets());
                req[20..22].copy_from_slice(&addr.port().to_be_bytes());
                stream.write_all(&req).await?;
            }
        }

        // Read reply (minimum 10 bytes for IPv4 reply)
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await?;
        if reply[0] != 0x05 || reply[1] != 0x00 {
            return Err(std::io::Error::other(format!(
                "SOCKS5 connect failed: reply status {:02x}",
                reply[1]
            )));
        }

        Ok(stream)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "socks5 connect timed out"))?
}

/// SOCKS5 CONNECT via domain name (ATYP 0x03). Returns a stream tunneled to
/// `host:port` through `proxy`. Bounded by `CONNECT_TIMEOUT` like
/// `socks5_connect` — the memleak leg dials real external hosts, so a
/// stalled handshake must not wedge the run forever.
pub async fn socks5_connect_domain(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        socks5_connect_domain_inner(proxy, host, port),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "socks5 connect timed out"))?
}

async fn socks5_connect_domain_inner(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    // Keep the load generator from adding Nagle/delayed-ACK stalls to the
    // proxy measurement, including immediately after the SOCKS handshake.
    stream.set_nodelay(true)?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 || buf[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 auth failed: {:02x} {:02x}",
            buf[0], buf[1]
        )));
    }

    let host_bytes = host.as_bytes();
    let len = host_bytes.len();
    if len > 255 {
        return Err(std::io::Error::other("domain name too long"));
    }
    // VER=5, CMD=CONNECT, RSV=0, ATYP=0x03 (domain), LEN, DOMAIN, PORT
    let mut req = Vec::with_capacity(4 + 1 + len + 2);
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, len as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 connect failed: reply status {:02x}",
            reply[1]
        )));
    }

    Ok(stream)
}
