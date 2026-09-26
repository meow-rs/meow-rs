//! UDP over TCP proxy implementation
//!
//! Implements the sing-box udp-over-tcp v2 protocol, both the Connect and the
//! Bind (non-connect) format.
//!
//! # Vendored-code note (meow-rs issue #625)
//!
//! The sequential `read_exact` framing reads below can leave the stream
//! mid-frame after a partial read error, desyncing subsequent packets —
//! the same class of bug fixed in `meow-proxy`'s Snell UDP path. There
//! are **no production-path callers** (meow-rs does not wire UDP-over-TCP
//! through the vendored `Server`; only `meow-proxy` integration tests
//! drive it). The note stands so the pattern is not copied into live
//! code without the fix.
//!
//! # Protocol Format
//!
//! ## Request (sent once at stream start):
//! ```text
//! | isConnect | ATYP | Address | Port |
//! | u8        | u8   | variable| u16be|
//! ```
//!
//! ## Data packets, Connect format (isConnect=1):
//! ```text
//! | Length | Data     |
//! | u16be  | variable |
//! ```
//!
//! ## Data packets, Bind format (isConnect=0):
//! ```text
//! | ATYP | Address | Port  | Length | Data     |
//! | u8   | variable| u16be | u16be  | variable |
//! ```
//!
//! Beware the asymmetry between the two address encodings: the *request*
//! address uses the SOCKS5 family bytes (`M.SocksaddrSerializer` upstream:
//! 0x01 IPv4 / 0x03 domain / 0x04 IPv6) while every *per-packet* address in
//! Bind format uses uot's own table (`uot.AddrParser`: 0x00 IPv4 / 0x01 IPv6 /
//! 0x02 domain). Sharing one table between them is silently wrong on the wire.
//!
//! Bind format is what mihomo's AnyTLS outbound speaks (`uot.NewLazyConn` with
//! `IsConnect` left false), so it is the format meow's own `AnytlsAdapter`
//! sends; Connect format is kept for clients that ask for it.
//!
//! Reference: <https://github.com/SagerNet/sing-box/blob/dev-next/docs/configuration/shared/udp-over-tcp.md>

use crate::session::{Stream, StreamReader};
use crate::util::{AnyTlsError, Result, resolve_host_with_cache};
use bytes::{BufMut, Bytes, BytesMut};
use meow_common::atomic::{AtomicU, Uint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::UdpSocket;
use tracing::{field, info_span};

const MAX_UDP_PACKET_SIZE: usize = 65535;

/// SOCKS5 address-family bytes — the initial request header only.
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// `uot.AddrParser` address-family bytes — Bind-format per-packet headers.
const UOT_ATYP_IPV4: u8 = 0x00;
const UOT_ATYP_IPV6: u8 = 0x01;
const UOT_ATYP_DOMAIN: u8 = 0x02;

/// A wire destination before any name resolution.
///
/// Kept unresolved so the Bind-format request address — which the peer sends
/// but the server never routes on — does not cost a DNS round-trip.
#[derive(Debug, Clone)]
enum AddrSpec {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl AddrSpec {
    /// Resolve to a socket address, hitting the shared DNS cache for domains.
    async fn resolve(&self) -> Result<SocketAddr> {
        match self {
            AddrSpec::Ip(addr) => Ok(*addr),
            AddrSpec::Domain(host, port) => resolve_host_with_cache(host, *port).await,
        }
    }
}

impl std::fmt::Display for AddrSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddrSpec::Ip(addr) => write!(f, "{}", addr),
            AddrSpec::Domain(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

/// Handle UDP over TCP stream
///
/// Target address should be "sp.v2.udp-over-tcp.arpa"
///
/// # Protocol
///
/// sing-box udp-over-tcp v2:
/// 1. First, read the initial request: isConnect + target address (SOCKS5 format)
/// 2. Then, each packet: Length (2 bytes BE) + Payload, prefixed by a uot
///    address when the request asked for Bind format (isConnect=0)
/// 3. Bidirectional forwarding between Stream and UDP socket
///
/// Reference: <https://github.com/SagerNet/sing-box/blob/dev-next/docs/configuration/shared/udp-over-tcp.md>
pub async fn handle_udp_over_tcp(stream: Arc<Stream>) -> Result<()> {
    let stream_id = stream.id();
    let udp_span = info_span!(
        "anytls.udp.proxy",
        stream_id,
        local_udp = field::Empty,
        target = field::Empty,
        packets_in = field::Empty,
        packets_out = field::Empty,
        bytes_in = field::Empty,
        bytes_out = field::Empty
    );
    let _udp_guard = udp_span.enter();

    tracing::debug!("[UDP] Starting UDP over TCP proxy for stream {}", stream_id);

    let reader = stream.reader();
    let mut reader_guard = reader.lock().await;

    // Step 1: Read initial request (isConnect + target address)
    // Format: isConnect + SOCKS5 address (ATYP + Address + Port)
    let (is_connect, target_spec) = match read_initial_request(&mut reader_guard).await {
        Ok(request) => request,
        Err(e) => {
            tracing::error!("[UDP] Failed to read initial request: {}", e);
            return Err(e);
        }
    };
    udp_span.record("target", field::display(&target_spec));

    tracing::debug!(
        "[UDP] {} format, target UDP address: {}",
        if is_connect { "Connect" } else { "Bind" },
        target_spec
    );

    drop(reader_guard);

    // Only Connect format pins a single destination for the whole stream; in
    // Bind format the request address is informational and every packet
    // carries its own, so resolving it here would be a pointless DNS lookup.
    let connect_target = if is_connect {
        Some(target_spec.resolve().await?)
    } else {
        None
    };

    // Step 2: Create UDP socket (bind to any available port)
    //
    // IPv4-only: Bind format lets the client name an arbitrary destination per
    // packet, so an IPv6 target fails at `send_to`. Acceptable here because
    // this server is a test/fork artifact — meow itself ships no anytls
    // inbound — but it is the first thing to change if that stops being true.
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
        tracing::error!("[UDP] Failed to create UDP socket: {}", e);
        AnyTlsError::Io(e)
    })?;

    let local_addr = udp_socket.local_addr()?;
    tracing::debug!("[UDP] Created UDP socket on {}", local_addr);
    udp_span.record("local_udp", field::display(local_addr));

    let packets_stream_to_udp = Arc::new(AtomicU::new(0));
    let bytes_stream_to_udp = Arc::new(AtomicU::new(0));
    let packets_udp_to_stream = Arc::new(AtomicU::new(0));
    let bytes_udp_to_stream = Arc::new(AtomicU::new(0));

    // Step 3: Send handshake success (if needed, similar to Go's ReportHandshakeSuccess)
    // In our case, we can just start forwarding

    // Step 4: Bidirectional forwarding
    tokio::select! {
        result = stream_to_udp(
            &stream,
            &udp_socket,
            connect_target.as_ref(),
            Arc::clone(&packets_stream_to_udp),
            Arc::clone(&bytes_stream_to_udp)
        ) => {
            if let Err(e) = result {
                tracing::error!("[UDP] Stream → UDP error: {}", e);
                return Err(e);
            }
        }
        result = udp_to_stream(
            &stream,
            &udp_socket,
            is_connect,
            Arc::clone(&packets_udp_to_stream),
            Arc::clone(&bytes_udp_to_stream)
        ) => {
            if let Err(e) = result {
                tracing::error!("[UDP] UDP → Stream error: {}", e);
                return Err(e);
            }
        }
    }

    let packets_out = packets_stream_to_udp.load(Ordering::Relaxed);
    let bytes_out = bytes_stream_to_udp.load(Ordering::Relaxed);
    let packets_in = packets_udp_to_stream.load(Ordering::Relaxed);
    let bytes_in = bytes_udp_to_stream.load(Ordering::Relaxed);
    udp_span.record("packets_out", packets_out);
    udp_span.record("bytes_out", bytes_out);
    udp_span.record("packets_in", packets_in);
    udp_span.record("bytes_in", bytes_in);

    tracing::debug!(
        "[UDP] UDP over TCP proxy completed for stream {} (packets_out={}, packets_in={})",
        stream_id,
        packets_out,
        packets_in
    );
    Ok(())
}

/// Read initial request from stream
///
/// Format (sing-box udp-over-tcp v2 request):
/// ```text
/// | isConnect | ATYP | Address | Port |
/// | u8        | u8   | variable| u16be|
/// ```
///
/// Returns `(is_connect, destination)`. The address is left unresolved: in
/// Bind format the server never routes on it.
async fn read_initial_request(reader: &mut StreamReader) -> Result<(bool, AddrSpec)> {
    // Read isConnect (1 byte)
    let mut is_connect_buf = [0u8; 1];
    reader
        .read_exact(&mut is_connect_buf)
        .await
        .map_err(AnyTlsError::Io)?;

    // Upstream writes a Go bool, so anything non-zero means Connect.
    let is_connect = is_connect_buf[0] != 0;

    let destination = read_socks5_addr(reader).await?;

    Ok((is_connect, destination))
}

/// Read a SOCKS5-serialized address (`M.SocksaddrSerializer` upstream).
///
/// Used by the initial request only — per-packet headers use
/// [`read_uot_addr`], whose family bytes differ.
async fn read_socks5_addr(reader: &mut StreamReader) -> Result<AddrSpec> {
    let mut atyp_buf = [0u8; 1];
    reader
        .read_exact(&mut atyp_buf)
        .await
        .map_err(AnyTlsError::Io)?;

    match atyp_buf[0] {
        SOCKS5_ATYP_IPV4 => read_ipv4_addr(reader).await,
        SOCKS5_ATYP_IPV6 => read_ipv6_addr(reader).await,
        SOCKS5_ATYP_DOMAIN => read_domain_addr(reader).await,
        other => Err(AnyTlsError::Protocol(format!(
            "Unknown address type: {}",
            other
        ))),
    }
}

/// Read a uot-serialized address (`uot.AddrParser` upstream).
///
/// Prefixes every Bind-format packet. Note the family bytes differ from the
/// SOCKS5 ones used by the request header.
async fn read_uot_addr(reader: &mut StreamReader) -> Result<AddrSpec> {
    let mut atyp_buf = [0u8; 1];
    reader
        .read_exact(&mut atyp_buf)
        .await
        .map_err(AnyTlsError::Io)?;

    match atyp_buf[0] {
        UOT_ATYP_IPV4 => read_ipv4_addr(reader).await,
        UOT_ATYP_IPV6 => read_ipv6_addr(reader).await,
        UOT_ATYP_DOMAIN => read_domain_addr(reader).await,
        other => Err(AnyTlsError::Protocol(format!(
            "Unknown uot address type: {}",
            other
        ))),
    }
}

/// IPv4: 4 bytes IP + 2 bytes port.
async fn read_ipv4_addr(reader: &mut StreamReader) -> Result<AddrSpec> {
    let mut ip_buf = [0u8; 4];
    reader
        .read_exact(&mut ip_buf)
        .await
        .map_err(AnyTlsError::Io)?;

    let port = read_port(reader).await?;
    Ok(AddrSpec::Ip(SocketAddr::from((
        std::net::Ipv4Addr::from(ip_buf),
        port,
    ))))
}

/// IPv6: 16 bytes IP + 2 bytes port.
async fn read_ipv6_addr(reader: &mut StreamReader) -> Result<AddrSpec> {
    let mut ip_buf = [0u8; 16];
    reader
        .read_exact(&mut ip_buf)
        .await
        .map_err(AnyTlsError::Io)?;

    let port = read_port(reader).await?;
    Ok(AddrSpec::Ip(SocketAddr::from((
        std::net::Ipv6Addr::from(ip_buf),
        port,
    ))))
}

/// Domain: length (1 byte) + domain + 2 bytes port.
async fn read_domain_addr(reader: &mut StreamReader) -> Result<AddrSpec> {
    let mut len_buf = [0u8; 1];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(AnyTlsError::Io)?;

    let domain_len = len_buf[0] as usize;
    if domain_len == 0 {
        return Err(AnyTlsError::Protocol("Invalid domain length".into()));
    }

    let mut domain_buf = vec![0u8; domain_len];
    reader
        .read_exact(&mut domain_buf)
        .await
        .map_err(AnyTlsError::Io)?;

    let domain = String::from_utf8(domain_buf)
        .map_err(|e| AnyTlsError::Protocol(format!("Invalid domain name: {}", e)))?;

    let port = read_port(reader).await?;
    Ok(AddrSpec::Domain(domain, port))
}

async fn read_port(reader: &mut StreamReader) -> Result<u16> {
    let mut port_buf = [0u8; 2];
    reader
        .read_exact(&mut port_buf)
        .await
        .map_err(AnyTlsError::Io)?;
    Ok(u16::from_be_bytes(port_buf))
}

/// Append a uot-serialized address (`uot.AddrParser` upstream).
///
/// IPv4-mapped IPv6 addresses are unmapped first, matching upstream's
/// `Socksaddr` normalization, so a dual-stack socket's `recv_from` peer does
/// not reach the client as `::ffff:a.b.c.d`.
fn encode_uot_addr(buf: &mut BytesMut, addr: &SocketAddr) {
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

/// Stream → UDP: Read packets from Stream, decode and send to UDP
///
/// Connect format: each packet is Length (2 bytes BE) + Payload, all bound for
/// `connect_target`. Bind format (`connect_target` is `None`): each packet is
/// prefixed by its own uot address, resolved per packet.
async fn stream_to_udp(
    stream: &Stream,
    udp: &UdpSocket,
    connect_target: Option<&SocketAddr>,
    packets_counter: Arc<AtomicU>,
    bytes_counter: Arc<AtomicU>,
) -> Result<()> {
    let stream_id = stream.id();
    let reader = stream.reader();
    let mut reader_guard = reader.lock().await;

    tracing::debug!("[UDP] Stream → UDP task started for stream {}", stream_id);

    loop {
        // Bind format carries a destination per packet; Connect format pinned
        // it once in the initial request.
        let target_addr = match connect_target {
            Some(addr) => *addr,
            None => match read_uot_addr(&mut reader_guard).await {
                Ok(spec) => match spec.resolve().await {
                    Ok(addr) => addr,
                    Err(e) => {
                        // A single unresolvable destination must not kill the
                        // whole association, but the length-prefixed payload
                        // still has to be drained to stay frame-aligned.
                        tracing::warn!("[UDP] Dropping packet for unresolvable target: {}", e);
                        match read_udp_packet(&mut reader_guard).await {
                            Ok(_) => continue,
                            Err(e) if is_eof(&e) => break,
                            Err(e) => return Err(e),
                        }
                    }
                },
                Err(e) => {
                    if is_eof(&e) {
                        tracing::debug!("[UDP] Stream closed (EOF), stopping Stream → UDP");
                        break;
                    }
                    tracing::error!("[UDP] Failed to read packet address: {}", e);
                    return Err(e);
                }
            },
        };

        // Read one UDP packet (Length + Payload format)
        let payload = match read_udp_packet(&mut reader_guard).await {
            Ok(data) => data,
            Err(e) => {
                if is_eof(&e) {
                    tracing::debug!("[UDP] Stream closed (EOF), stopping Stream → UDP");
                    break;
                }
                tracing::error!("[UDP] Failed to read UDP packet from stream: {}", e);
                return Err(e);
            }
        };

        if payload.is_empty() {
            tracing::debug!("[UDP] Empty packet, stream might be closed");
            break;
        }

        tracing::trace!(
            "[UDP] Stream → UDP: {} bytes to {}",
            payload.len(),
            target_addr
        );

        // Send to UDP (target from the initial request or this packet's header)
        let sent = udp.send_to(&payload, target_addr).await?;

        if sent != payload.len() {
            tracing::warn!("[UDP] Partial UDP send: {} / {} bytes", sent, payload.len());
        }
        packets_counter.fetch_add(1, Ordering::Relaxed);
        bytes_counter.fetch_add(sent as Uint, Ordering::Relaxed);
    }

    Ok(())
}

/// UDP → Stream: Read from UDP, encode and send to Stream
///
/// Connect format: each packet is Length (2 bytes BE) + Payload — the client
/// already knows the peer. Bind format: the source address is prefixed in uot
/// encoding so the client can demultiplex.
async fn udp_to_stream(
    stream: &Stream,
    udp: &UdpSocket,
    is_connect: bool,
    packets_counter: Arc<AtomicU>,
    bytes_counter: Arc<AtomicU>,
) -> Result<()> {
    let stream_id = stream.id();

    tracing::debug!("[UDP] UDP → Stream task started for stream {}", stream_id);

    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];

    loop {
        // Receive from UDP
        let (len, addr) = match udp.recv_from(&mut buf).await {
            Ok((len, addr)) => (len, addr),
            Err(e) => {
                tracing::error!("[UDP] Failed to receive from UDP: {}", e);
                return Err(AnyTlsError::Io(e));
            }
        };

        tracing::trace!("[UDP] UDP → Stream: {} bytes from {}", len, addr);

        let packet = if is_connect {
            encode_udp_packet_simple(&buf[..len])?
        } else {
            encode_udp_packet_from(&buf[..len], &addr)?
        };

        // Send to Stream using the send_data method
        if let Err(e) = stream.send_data(packet).await {
            tracing::error!("[UDP] Failed to send to stream: {}", e);
            return Err(AnyTlsError::Protocol("Channel send failed".into()));
        }
        packets_counter.fetch_add(1, Ordering::Relaxed);
        bytes_counter.fetch_add(len as Uint, Ordering::Relaxed);
    }
}

/// Whether a read error means the peer closed the stream rather than a real
/// protocol fault. `StreamReader::read_exact` reports a short read as
/// `UnexpectedEof`.
fn is_eof(err: &AnyTlsError) -> bool {
    match err {
        AnyTlsError::Io(e) => e.kind() == std::io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

/// Read one UDP packet from Stream
///
/// Format: | Length (2 bytes BE) | Payload |
/// Returns the payload (without length prefix)
async fn read_udp_packet(reader: &mut StreamReader) -> Result<Vec<u8>> {
    // Read 2-byte length (Big-Endian)
    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(AnyTlsError::Io)?;

    let len = u16::from_be_bytes(len_buf) as usize;

    if len == 0 {
        return Ok(Vec::new());
    }

    if len > MAX_UDP_PACKET_SIZE {
        return Err(AnyTlsError::Protocol(format!(
            "UDP packet too large: {} bytes",
            len
        )));
    }

    // Read the actual payload
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .map_err(AnyTlsError::Io)?;

    Ok(data)
}

/// Encode UDP packet (simple format)
///
/// Format (sing-box v2 after initial request):
/// | Length (2 bytes BE) | Payload |
///
/// The payload is pure UDP data (no address encoding needed)
fn encode_udp_packet_simple(payload: &[u8]) -> Result<Bytes> {
    let mut buf = BytesMut::new();

    if payload.len() > MAX_UDP_PACKET_SIZE {
        return Err(AnyTlsError::Protocol(format!(
            "UDP packet too large: {} bytes",
            payload.len()
        )));
    }

    // Write length (2 bytes, Big-Endian)
    buf.put_u16(payload.len() as u16);

    // Write payload
    buf.put_slice(payload);

    Ok(buf.freeze())
}

/// Encode a Bind-format UDP packet.
///
/// Format: | uot address | Length (2 bytes BE) | Payload |
///
/// One anytls data frame carries a `u16` length and the codec truncates
/// silently on overflow, so the whole framed packet — not just the payload —
/// has to fit. The largest header is 19 bytes (IPv6) + 2 for the length, which
/// still leaves room for a maximum-size UDP datagram.
fn encode_udp_packet_from(payload: &[u8], from: &SocketAddr) -> Result<Bytes> {
    if payload.len() > MAX_UDP_PACKET_SIZE {
        return Err(AnyTlsError::Protocol(format!(
            "UDP packet too large: {} bytes",
            payload.len()
        )));
    }

    let mut buf = BytesMut::with_capacity(payload.len() + 21);
    encode_uot_addr(&mut buf, from);
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);

    if buf.len() > MAX_UDP_PACKET_SIZE {
        return Err(AnyTlsError::Protocol(format!(
            "Framed UDP packet too large: {} bytes",
            buf.len()
        )));
    }

    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_udp_packet_length() {
        // Test that we can encode and decode length correctly
        let payload = b"Test UDP data";
        let encoded = encode_udp_packet_simple(payload).unwrap();

        // Check length prefix
        let len = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
        assert_eq!(len, payload.len());
        assert_eq!(encoded.len(), 2 + payload.len());

        // Check payload
        assert_eq!(&encoded[2..], payload);
    }

    #[test]
    fn test_encode_empty_packet() {
        let payload = b"";
        let encoded = encode_udp_packet_simple(payload).unwrap();

        // Should have 2-byte length header with value 0
        assert_eq!(encoded.len(), 2);
        assert_eq!(u16::from_be_bytes([encoded[0], encoded[1]]), 0);
    }

    #[test]
    fn test_encode_large_packet() {
        let payload = vec![0u8; 65535]; // Max UDP packet size
        let result = encode_udp_packet_simple(&payload);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        assert_eq!(encoded.len(), 2 + 65535);
        assert_eq!(u16::from_be_bytes([encoded[0], encoded[1]]), 65535);
    }

    #[test]
    fn test_encode_too_large_packet() {
        let payload = vec![0u8; 65536]; // Too large
        let result = encode_udp_packet_simple(&payload);
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("too large"));
        }
    }
}
