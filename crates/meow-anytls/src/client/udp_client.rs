//! Client-side UDP over TCP implementation
//!
//! Implements sing-box udp-over-tcp v2 protocol (Connect format)
//!
//! # Vendored-code note (meow-rs issue #625)
//!
//! The sequential `read_exact` framing reads in `read_udp_packet` can
//! leave the stream mid-frame after a partial read error, desyncing
//! subsequent packets — the same class of bug fixed in `meow-proxy`'s
//! Snell UDP path. This module has **zero in-tree callers** (meow-rs
//! does not wire UDP-over-TCP through the vendored client); the note
//! stands so the pattern is not copied into live code without the fix.

use crate::client::Client;
use crate::util::{AnyTlsError, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const MAX_UDP_PACKET_SIZE: usize = 65535;

/// Magic address for UDP over TCP v2
pub const UDP_OVER_TCP_MAGIC_ADDR: &str = "sp.v2.udp-over-tcp.arpa";

impl Client {
    /// Create a UDP over TCP proxy connection
    ///
    /// This creates a special stream to the magic address "sp.v2.udp-over-tcp.arpa"
    /// and then sends the actual UDP target address in the initial request.
    ///
    /// # Arguments
    /// * `local_addr` - Local address to bind UDP socket to (e.g. "127.0.0.1:0")
    /// * `target_addr` - Target UDP server address
    ///
    /// # Returns
    /// Local UDP socket address that the application should connect to
    pub async fn create_udp_proxy(
        &self,
        local_addr: &str,
        target_addr: SocketAddr,
    ) -> Result<SocketAddr> {
        tracing::debug!(
            "[UDP Client] Creating UDP over TCP proxy: local={}, target={}",
            local_addr,
            target_addr
        );

        // Step 1: Create a stream to the magic address, flushing the initial
        // request (isConnect + target address) before the SYNACK wait — a
        // sing-box inbound reads the request before it SYNACKs, so sending it
        // after the stream is returned deadlocks (meow-rs issue #535).
        let initial_request = encode_initial_request(target_addr)?;
        let magic_destination = (UDP_OVER_TCP_MAGIC_ADDR.to_string(), 0);
        let (stream, _session) = self
            .create_proxy_stream_with_payload(magic_destination, Some(initial_request))
            .await?;

        tracing::debug!(
            "[UDP Client] Created stream {} for UDP over TCP",
            stream.id()
        );

        // Step 2: Create local UDP socket via the socket-protect helper so a
        // host VPN (Android) can call `VpnService.protect(fd)` before the
        // bind — otherwise relayed datagrams loop back into the same VPN.
        // Off-Android the helper degrades to `UdpSocket::bind`.
        let local_udp = crate::util::socket_protect::bind_udp(local_addr)
            .await
            .map_err(|e| {
                tracing::error!("[UDP Client] Failed to bind UDP socket: {}", e);
                AnyTlsError::Io(e)
            })?;

        let bound_addr = local_udp.local_addr()?;
        tracing::debug!("[UDP Client] Local UDP socket bound to {}", bound_addr);

        // Step 3: Start bidirectional forwarding
        let stream_clone = stream.clone();

        tokio::spawn(async move {
            if let Err(e) = udp_proxy_loop(local_udp, stream_clone).await {
                tracing::error!("[UDP Client] Proxy loop error: {}", e);
            }
        });

        tracing::debug!(
            "[UDP Client] UDP proxy started: {} <-> {}",
            bound_addr,
            target_addr
        );

        Ok(bound_addr)
    }
}

/// Encode initial request for UDP over TCP v2
///
/// Format:
/// ```text
/// | isConnect | ATYP | Address | Port |
/// | u8 (=1)   | u8   | variable| u16be|
/// ```
fn encode_initial_request(target: SocketAddr) -> Result<Bytes> {
    let mut buf = BytesMut::new();

    // isConnect = 1 (use Connect format)
    buf.put_u8(1);

    // Encode target address in SOCKS5 format
    match target {
        SocketAddr::V4(addr) => {
            buf.put_u8(0x01); // IPv4
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
        SocketAddr::V6(addr) => {
            buf.put_u8(0x04); // IPv6
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
    }

    Ok(buf.freeze())
}

/// Main UDP proxy loop: bidirectional forwarding between local UDP and remote stream
async fn udp_proxy_loop(local_udp: UdpSocket, stream: Arc<crate::session::Stream>) -> Result<()> {
    let stream_id = stream.id();

    tracing::debug!("[UDP Client] Starting proxy loop for stream {}", stream_id);

    let last_peer = Arc::new(Mutex::new(None::<SocketAddr>));

    // Bidirectional forwarding
    tokio::select! {
        result = udp_to_stream(&local_udp, &stream, last_peer.clone()) => {
            if let Err(e) = result {
                tracing::error!("[UDP Client] UDP → Stream error: {}", e);
                return Err(e);
            }
        }
        result = stream_to_udp(&local_udp, &stream, last_peer.clone()) => {
            if let Err(e) = result {
                tracing::error!("[UDP Client] Stream → UDP error: {}", e);
                return Err(e);
            }
        }
    }

    Ok(())
}

/// UDP → Stream: Read from local UDP, encode and send to stream
async fn udp_to_stream(
    udp: &UdpSocket,
    stream: &Arc<crate::session::Stream>,
    last_peer: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    let stream_id = stream.id();

    tracing::debug!(
        "[UDP Client] UDP → Stream task started for stream {}",
        stream_id
    );

    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];

    loop {
        // Receive from local UDP
        let (len, addr) = match udp.recv_from(&mut buf).await {
            Ok((len, addr)) => (len, addr),
            Err(e) => {
                tracing::error!("[UDP Client] Failed to receive from UDP: {}", e);
                return Err(AnyTlsError::Io(e));
            }
        };

        {
            let mut guard = last_peer.lock().await;
            *guard = Some(addr);
        }

        tracing::trace!("[UDP Client] UDP → Stream: {} bytes from {}", len, addr);

        // Encode packet: Length (2 bytes) + Data
        let packet = encode_udp_packet(&buf[..len])?;

        // Send to stream
        stream.send_data(packet).await.map_err(|e| {
            tracing::error!("[UDP Client] Failed to send to stream: {}", e);
            AnyTlsError::Protocol("Channel send failed".into())
        })?;
    }
}

/// Stream → UDP: Read from stream, decode and send to local UDP
async fn stream_to_udp(
    udp: &UdpSocket,
    stream: &Arc<crate::session::Stream>,
    last_peer: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    let stream_id = stream.id();
    let reader = stream.reader();

    tracing::debug!(
        "[UDP Client] Stream → UDP task started for stream {}",
        stream_id
    );

    // We need to track the peer address for sending back
    // In a real implementation, the first packet might contain address info
    // For now, we'll just send to a fixed address or handle it differently
    loop {
        let mut reader_guard = reader.lock().await;

        // Read one UDP packet (Length + Data format)
        let payload = match read_udp_packet(&mut reader_guard).await {
            Ok(data) => data,
            Err(e) => {
                if e.to_string().contains("UnexpectedEof") || e.to_string().contains("EOF") {
                    tracing::debug!("[UDP Client] Stream closed (EOF), stopping Stream → UDP");
                    break;
                }
                tracing::error!("[UDP Client] Failed to read UDP packet from stream: {}", e);
                return Err(e);
            }
        };

        drop(reader_guard);

        if payload.is_empty() {
            tracing::debug!("[UDP Client] Empty packet, stream might be closed");
            break;
        }

        tracing::trace!("[UDP Client] Stream → UDP: {} bytes", payload.len());

        // Determine the most recent peer address we received from
        let target = { *last_peer.lock().await };

        if let Some(addr) = target {
            let sent = udp.send_to(&payload, addr).await?;

            if sent != payload.len() {
                tracing::warn!(
                    "[UDP Client] Partial UDP send: {} / {} bytes",
                    sent,
                    payload.len()
                );
            }
        } else {
            tracing::warn!(
                "[UDP Client] No peer address known yet, dropping {}-byte packet",
                payload.len()
            );
        }
    }

    Ok(())
}

/// Read one UDP packet from stream
///
/// Format: | Length (2 bytes BE) | Payload |
async fn read_udp_packet(reader: &mut crate::session::StreamReader) -> Result<Vec<u8>> {
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
/// Format: | Length (2 bytes BE) | Payload |
fn encode_udp_packet(payload: &[u8]) -> Result<Bytes> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_initial_request_ipv4() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let encoded = encode_initial_request(addr).unwrap();

        // Should be: isConnect (1) + ATYP (1) + IPv4 (4) + Port (2) = 8 bytes
        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded[0], 1); // isConnect = 1
        assert_eq!(encoded[1], 0x01); // IPv4
        assert_eq!(&encoded[2..6], &[8, 8, 8, 8]); // IP
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 53); // Port
    }

    #[test]
    fn test_encode_initial_request_ipv6() {
        let addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        let encoded = encode_initial_request(addr).unwrap();

        // Should be: isConnect (1) + ATYP (1) + IPv6 (16) + Port (2) = 20 bytes
        assert_eq!(encoded.len(), 20);
        assert_eq!(encoded[0], 1); // isConnect = 1
        assert_eq!(encoded[1], 0x04); // IPv6
        assert_eq!(u16::from_be_bytes([encoded[18], encoded[19]]), 53); // Port
    }

    #[test]
    fn test_encode_udp_packet() {
        let payload = b"Hello, UDP!";
        let encoded = encode_udp_packet(payload).unwrap();

        // Check length prefix
        let len = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
        assert_eq!(len, payload.len());
        assert_eq!(encoded.len(), 2 + payload.len());

        // Check payload
        assert_eq!(&encoded[2..], payload);
    }
}
