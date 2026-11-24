//! AnyTLS wire helpers shared by the dev `server` fixture and the
//! production `type: anytls` inbound listener: the SOCKS5-serialized
//! destination every stream leads with, and the sing-box udp-over-tcp
//! v2 (UoT) request/packet codec.
//!
//! # Formats
//!
//! Stream destination / UoT request address (`M.SocksaddrSerializer`):
//! `ATYP u8 | address | port u16be` with ATYP 0x01 IPv4 / 0x03 domain /
//! 0x04 IPv6.
//!
//! UoT request (once per stream): `isConnect u8 | <socks addr>`.
//! Connect packets: `len u16be | payload`. Bind packets:
//! `<uot addr> | len u16be | payload` where the uot address uses its own
//! family table (0x00 IPv4 / 0x01 IPv6 / 0x02 domain) — NOT the SOCKS5
//! one. Sharing a table between the two is silently wrong on the wire.
//!
//! Reference: <https://github.com/SagerNet/sing-box/blob/dev-next/docs/configuration/shared/udp-over-tcp.md>

use crate::util::{AnyTlsError, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use tokio::io::AsyncRead;

/// Magic destination that marks a logical stream as a UoT v2
/// association. Only `sp.v2.udp-over-tcp.arpa:0` is a UoT stream — the
/// legacy `sp.udp-over-tcp.arpa` name and a non-zero port on the v2 name
/// are refused, never routed as TCP.
pub const UOT_V2_DOMAIN: &str = "sp.v2.udp-over-tcp.arpa";
/// Legacy (v1) UoT domain — explicitly rejected upstream too.
pub const UOT_LEGACY_DOMAIN: &str = "sp.udp-over-tcp.arpa";

const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

const UOT_ATYP_IPV4: u8 = 0x00;
const UOT_ATYP_IPV6: u8 = 0x01;
const UOT_ATYP_DOMAIN: u8 = 0x02;

const MAX_UDP_PACKET_SIZE: usize = 65535;

/// A wire destination before any name resolution.
#[derive(Debug, Clone)]
pub enum UotAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl UotAddr {
    /// Host form for `Metadata.host` — the literal IP for `Ip`, the
    /// domain verbatim for `Domain`.
    pub fn host(&self) -> String {
        match self {
            UotAddr::Ip(addr) => addr.ip().to_string(),
            UotAddr::Domain(host, _) => host.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            UotAddr::Ip(addr) => addr.port(),
            UotAddr::Domain(_, port) => *port,
        }
    }

    /// True when this stream destination opens a UoT v2 association —
    /// exactly `sp.v2.udp-over-tcp.arpa:0`.
    pub fn is_uot_v2(&self) -> bool {
        matches!(self, UotAddr::Domain(host, 0) if host == UOT_V2_DOMAIN)
    }

    /// True when this stream destination is any *rejected* UoT form:
    /// the legacy domain (any port) or the v2 domain on a port other
    /// than 0. Must not be treated as an ordinary TCP destination.
    /// Mutually exclusive with [`is_uot_v2`](Self::is_uot_v2) — the
    /// legal marker `sp.v2.udp-over-tcp.arpa:0` is neither.
    pub fn is_uot_rejected(&self) -> bool {
        match self {
            UotAddr::Domain(host, port) => {
                host == UOT_LEGACY_DOMAIN || (host == UOT_V2_DOMAIN && *port != 0)
            }
            UotAddr::Ip(_) => false,
        }
    }
}

impl std::fmt::Display for UotAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UotAddr::Ip(addr) => write!(f, "{addr}"),
            UotAddr::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

async fn read_exact<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    use tokio::io::AsyncReadExt;
    reader.read_exact(buf).await.map_err(AnyTlsError::Io)?;
    Ok(())
}

/// Read a SOCKS5-serialized address — the stream destination and the UoT
/// request address.
pub async fn read_socks_addr<R: AsyncRead + Unpin>(reader: &mut R) -> Result<UotAddr> {
    let mut atyp = [0u8; 1];
    read_exact(reader, &mut atyp).await?;
    match atyp[0] {
        SOCKS5_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            read_exact(reader, &mut ip).await?;
            Ok(UotAddr::Ip(SocketAddr::from((
                std::net::Ipv4Addr::from(ip),
                read_port(reader).await?,
            ))))
        }
        SOCKS5_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            read_exact(reader, &mut ip).await?;
            Ok(UotAddr::Ip(SocketAddr::from((
                std::net::Ipv6Addr::from(ip),
                read_port(reader).await?,
            ))))
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(reader, &mut len).await?;
            if len[0] == 0 {
                return Err(AnyTlsError::Protocol("invalid domain length".into()));
            }
            let mut domain = vec![0u8; len[0] as usize];
            read_exact(reader, &mut domain).await?;
            let domain = String::from_utf8(domain)
                .map_err(|e| AnyTlsError::Protocol(format!("invalid domain name: {e}")))?;
            Ok(UotAddr::Domain(domain, read_port(reader).await?))
        }
        other => Err(AnyTlsError::Protocol(format!(
            "unknown address type: {other}"
        ))),
    }
}

async fn read_port<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u16> {
    let mut port = [0u8; 2];
    read_exact(reader, &mut port).await?;
    Ok(u16::from_be_bytes(port))
}

/// Read a uot-serialized address (`uot.AddrParser`) — prefixes every
/// Bind-format packet. Family bytes differ from the SOCKS5 table.
pub async fn read_uot_addr<R: AsyncRead + Unpin>(reader: &mut R) -> Result<UotAddr> {
    let mut atyp = [0u8; 1];
    read_exact(reader, &mut atyp).await?;
    match atyp[0] {
        UOT_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            read_exact(reader, &mut ip).await?;
            Ok(UotAddr::Ip(SocketAddr::from((
                std::net::Ipv4Addr::from(ip),
                read_port(reader).await?,
            ))))
        }
        UOT_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            read_exact(reader, &mut ip).await?;
            Ok(UotAddr::Ip(SocketAddr::from((
                std::net::Ipv6Addr::from(ip),
                read_port(reader).await?,
            ))))
        }
        UOT_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(reader, &mut len).await?;
            if len[0] == 0 {
                return Err(AnyTlsError::Protocol("invalid domain length".into()));
            }
            let mut domain = vec![0u8; len[0] as usize];
            read_exact(reader, &mut domain).await?;
            let domain = String::from_utf8(domain)
                .map_err(|e| AnyTlsError::Protocol(format!("invalid domain name: {e}")))?;
            Ok(UotAddr::Domain(domain, read_port(reader).await?))
        }
        other => Err(AnyTlsError::Protocol(format!(
            "unknown uot address type: {other}"
        ))),
    }
}

/// Read the UoT initial request: `isConnect u8 | <socks addr>`.
/// Returns `(is_connect, destination)`.
///
/// Connect's address is a parsed/validated [`UotAddr`] — it is the
/// association's one fixed target. Bind's address is a placeholder the
/// spec's `uot.Server` only consumes by layout — the same family table
/// is skipped verbatim, never interpreted, so an unusual placeholder
/// cannot reject a legal Bind association (`None` returned for it).
pub async fn read_uot_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(bool, Option<UotAddr>)> {
    let mut is_connect = [0u8; 1];
    read_exact(reader, &mut is_connect).await?;
    // Upstream writes a Go bool: anything non-zero means Connect.
    if is_connect[0] != 0 {
        Ok((true, Some(read_socks_addr(reader).await?)))
    } else {
        skip_socks_addr(reader).await?;
        Ok((false, None))
    }
}

/// Consume a SOCKS5-serialized address by layout only — same family
/// table and byte counts as [`read_socks_addr`], none of the value
/// checks (UTF-8, non-empty domain). For positions where the address
/// must be skipped rather than interpreted (the Bind request slot).
async fn skip_socks_addr<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut atyp = [0u8; 1];
    read_exact(reader, &mut atyp).await?;
    let addr_len = match atyp[0] {
        SOCKS5_ATYP_IPV4 => 4,
        SOCKS5_ATYP_IPV6 => 16,
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(reader, &mut len).await?;
            len[0] as usize
        }
        other => {
            return Err(AnyTlsError::Protocol(format!(
                "unknown address type: {other}"
            )));
        }
    };
    let mut skip = vec![0u8; addr_len + 2];
    read_exact(reader, &mut skip).await?;
    Ok(())
}

/// Read one length-prefixed UoT packet (`len u16be | payload`).
/// Returns the payload without the prefix; an empty `Ok` payload is a
/// zero-length datagram the caller must still forward.
pub async fn read_uot_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Bytes> {
    let mut len = [0u8; 2];
    read_exact(reader, &mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 {
        return Ok(Bytes::new());
    }
    let mut data = vec![0u8; len];
    read_exact(reader, &mut data).await?;
    Ok(Bytes::from(data))
}

/// Append a uot-serialized address. IPv4-mapped IPv6 addresses are
/// unmapped first (upstream `Socksaddr` normalization), so a dual-stack
/// socket's reply source does not reach the client as `::ffff:a.b.c.d`.
pub fn encode_uot_addr(buf: &mut BytesMut, addr: &SocketAddr) {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            buf.put_u8(UOT_ATYP_IPV4);
            buf.put_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                buf.put_u8(UOT_ATYP_IPV4);
                buf.put_slice(&v4.octets());
            }
            None => {
                buf.put_u8(UOT_ATYP_IPV6);
                buf.put_slice(&v6.octets());
            }
        },
    }
    buf.put_u16(addr.port());
}

/// Encode a Connect-format reply packet: `len u16be | payload`.
pub fn encode_uot_packet_simple(payload: &[u8]) -> Result<Bytes> {
    if payload.len() > MAX_UDP_PACKET_SIZE {
        return Err(AnyTlsError::Protocol(format!(
            "UDP packet too large: {} bytes",
            payload.len()
        )));
    }
    let mut buf = BytesMut::with_capacity(2 + payload.len());
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);
    Ok(buf.freeze())
}

/// Encode a Bind-format reply packet: `<uot addr> | len u16be | payload`.
/// `src` is the reply's real source address.
pub fn encode_uot_packet_from(payload: &[u8], src: &SocketAddr) -> Result<Bytes> {
    if payload.len() > MAX_UDP_PACKET_SIZE {
        return Err(AnyTlsError::Protocol(format!(
            "UDP packet too large: {} bytes",
            payload.len()
        )));
    }
    let mut buf = BytesMut::with_capacity(24 + payload.len());
    encode_uot_addr(&mut buf, src);
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);
    Ok(buf.freeze())
}

/// Whether a read error means the peer closed the stream rather than a
/// real protocol fault — the sequential `read_exact` framing reports a
/// short read as `UnexpectedEof`.
pub fn is_eof(err: &AnyTlsError) -> bool {
    matches!(err, AnyTlsError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn socks_domain_bytes(host: &str, port: u16) -> Vec<u8> {
        let mut buf = vec![SOCKS5_ATYP_DOMAIN, host.len() as u8];
        buf.extend_from_slice(host.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    #[tokio::test]
    async fn socks_addr_decodes_every_family() {
        let v4 = [0x01, 127, 0, 0, 1, 0x1F, 0x90];
        let UotAddr::Ip(addr) = read_socks_addr(&mut &v4[..]).await.unwrap() else {
            panic!("expected Ip");
        };
        assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());

        let mut v6 = vec![0x04];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        let UotAddr::Ip(addr) = read_socks_addr(&mut &v6[..]).await.unwrap() else {
            panic!("expected Ip");
        };
        assert_eq!(addr, "[::1]:443".parse().unwrap());

        let domain = socks_domain_bytes("example.com", 443);
        let UotAddr::Domain(host, port) = read_socks_addr(&mut &domain[..]).await.unwrap() else {
            panic!("expected Domain");
        };
        assert_eq!((host.as_str(), port), ("example.com", 443));

        assert!(read_socks_addr(&mut &[0x02u8, 1][..]).await.is_err());
        assert!(read_socks_addr(&mut &[0x03u8, 0][..]).await.is_err());
    }

    #[tokio::test]
    async fn uot_marker_is_exact_and_rejects_never_route() {
        // Only `sp.v2.udp-over-tcp.arpa:0` opens a UoT association.
        let bytes = socks_domain_bytes(UOT_V2_DOMAIN, 0);
        let addr = read_socks_addr(&mut &bytes[..]).await.unwrap();
        assert!(addr.is_uot_v2());
        // The legal marker is neither rejected nor plain TCP — the
        // predicates are mutually exclusive so either dispatch order is
        // safe (F01: the rejected check used to swallow the marker).
        assert!(!addr.is_uot_rejected());

        // v2 name on any other port: rejected, not an association.
        let bytes = socks_domain_bytes(UOT_V2_DOMAIN, 53);
        let addr = read_socks_addr(&mut &bytes[..]).await.unwrap();
        assert!(!addr.is_uot_v2());
        assert!(addr.is_uot_rejected());

        // Legacy v1 name: rejected on every port including 0.
        for port in [0u16, 53] {
            let bytes = socks_domain_bytes(UOT_LEGACY_DOMAIN, port);
            let addr = read_socks_addr(&mut &bytes[..]).await.unwrap();
            assert!(!addr.is_uot_v2());
            assert!(addr.is_uot_rejected());
        }

        // Ordinary destinations are neither.
        let bytes = socks_domain_bytes("example.com", 443);
        let addr = read_socks_addr(&mut &bytes[..]).await.unwrap();
        assert!(!addr.is_uot_v2());
        assert!(!addr.is_uot_rejected());
    }

    #[tokio::test]
    async fn uot_family_table_differs_from_socks() {
        // The two family tables share no codepoint for IPv4: a Bind
        // packet address decoded with the SOCKS5 table is an error, not
        // a misdecode — the exact pitfall this module exists to prevent.
        let mut buf = BytesMut::new();
        encode_uot_addr(&mut buf, &"192.0.2.1:1234".parse().unwrap());
        assert_eq!(buf[0], UOT_ATYP_IPV4); // 0x00 — invalid under SOCKS5
        assert!(read_socks_addr(&mut &buf[..]).await.is_err());

        let addr = read_uot_addr(&mut &buf[..]).await.unwrap();
        assert!(matches!(addr, UotAddr::Ip(a) if a == "192.0.2.1:1234".parse().unwrap()));

        // IPv4-mapped IPv6 unmaps onto the wire's v4 form.
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:53".parse().unwrap();
        let mut buf = BytesMut::new();
        encode_uot_addr(&mut buf, &mapped);
        assert_eq!(buf[0], UOT_ATYP_IPV4);
        assert_eq!(&buf[1..5], &[192, 0, 2, 1]);
    }

    #[tokio::test]
    async fn uot_request_and_packet_framing() {
        // Request: isConnect u8 | socks addr. Go bool semantics — any
        // non-zero is Connect.
        let mut wire = vec![0x01];
        wire.extend_from_slice(&socks_domain_bytes("203.0.113.9.example", 0));
        let (is_connect, dest) = read_uot_request(&mut &wire[..]).await.unwrap();
        assert!(is_connect);
        assert!(matches!(dest, Some(UotAddr::Domain(_, 0))));
        wire[0] = 0x00;
        let (is_connect, dest) = read_uot_request(&mut &wire[..]).await.unwrap();
        assert!(!is_connect);
        assert!(dest.is_none(), "bind request dest is layout-consumed");

        // Bind placeholder addresses are never interpreted: an empty
        // domain that `read_socks_addr` rejects parses fine as a Bind
        // request.
        let mut wire = vec![0x00, 0x03, 0x00, 0x04, 0x00];
        let (is_connect, dest) = read_uot_request(&mut &wire[..]).await.unwrap();
        assert!(!is_connect && dest.is_none());
        // ...but the layout boundary still holds — a following packet
        // decodes right after the skipped placeholder address.
        wire.extend_from_slice(&[0x00, 0x01, 0xAA]);
        assert_eq!(
            &read_uot_packet(&mut &wire[5..]).await.unwrap()[..],
            &[0xAA]
        );

        // Connect packets are a bare u16be length + payload; zero length
        // is a real (empty) datagram, not EOF.
        let wire = [0x00, 0x03, b'a', b'b', b'c'];
        assert_eq!(&read_uot_packet(&mut &wire[..]).await.unwrap()[..], b"abc");
        let wire = [0x00, 0x00];
        assert!(read_uot_packet(&mut &wire[..]).await.unwrap().is_empty());

        // Encoders round-trip through the matching readers.
        let simple = encode_uot_packet_simple(b"payload").unwrap();
        assert_eq!(
            &read_uot_packet(&mut &simple[..]).await.unwrap()[..],
            b"payload"
        );

        let bind = encode_uot_packet_from(b"pong", &"10.0.0.2:5353".parse().unwrap()).unwrap();
        let mut cursor: &[u8] = &bind[..];
        let src = read_uot_addr(&mut cursor).await.unwrap();
        assert!(matches!(src, UotAddr::Ip(a) if a == "10.0.0.2:5353".parse().unwrap()));
        assert_eq!(&read_uot_packet(&mut cursor).await.unwrap()[..], b"pong");

        // 64 KiB+ payloads are refused before they truncate a u16.
        let oversize = vec![0u8; MAX_UDP_PACKET_SIZE + 1];
        assert!(encode_uot_packet_simple(&oversize).is_err());
        assert!(encode_uot_packet_from(&oversize, &"10.0.0.2:1".parse().unwrap()).is_err());
    }

    #[test]
    fn uot_addr_display_and_host() {
        let ip = UotAddr::Ip("192.0.2.1:53".parse().unwrap());
        assert_eq!(ip.host(), "192.0.2.1");
        assert_eq!(ip.port(), 53);
        assert_eq!(ip.to_string(), "192.0.2.1:53");
        let domain = UotAddr::Domain("example.com".into(), 443);
        assert_eq!(domain.host(), "example.com");
        assert_eq!(domain.to_string(), "example.com:443");
    }
}
