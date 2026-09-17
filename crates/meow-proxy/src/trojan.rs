//! Trojan outbound proxy adapter.
//!
//! TLS is provided by `meow_transport::tls::TlsLayer` (M1.A-1 migration).
//! Protocol logic — SHA-224 password hash, CRLF header, SOCKS5 address
//! encoding — remains here unchanged.
//!
//! UDP relay (CMD=0x03 UDP_ASSOCIATE) tunnels packets over the same TLS
//! stream as TCP.  Each datagram is framed as
//! `ATYP | DST.ADDR | DST.PORT | LENGTH(u16 BE) | CRLF | PAYLOAD`,
//! matching trojan-go / clash-meta upstream.

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_transport::{
    tls::{TlsConfig, TlsLayer},
    Stream as TransportStream, Transport,
};
use sha2::{Digest, Sha224};
use smol_str::SmolStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tracing::debug;

#[cfg(feature = "mux")]
use crate::mux::{MuxClient, MuxOptions};
use crate::stream_conn::StreamConn;
use crate::transport_to_proxy_err;
use std::sync::Arc;

/// SOCKS5-style command bytes used inside the Trojan request header.
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// SOCKS5 address types.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const MAX_DOMAIN_LEN: usize = u8::MAX as usize;
const TROJAN_HEADER_BUF_SIZE: usize = 320;

pub struct TrojanAdapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    addr_str: SmolStr,
    hex_password: SmolStr,
    support_udp: bool,
    health: ProxyHealth,
    tls_layer: Arc<TlsLayer>,
    /// Pluggable TCP dialer for the underlying connection to the proxy
    /// server (direct or via dialer-proxy).
    dialer: Arc<dyn crate::dialer::TcpDialer>,
    /// sing-mux compatible connection multiplexing (optional).
    #[cfg(feature = "mux")]
    mux: Option<Arc<MuxClient>>,
}

impl TrojanAdapter {
    #[allow(
        clippy::too_many_arguments,
        reason = "dialer param for pluggable TcpDialer"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: &str,
        skip_verify: bool,
        udp: bool,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Self {
        // SHA-224 hash of password, hex-encoded = 56 chars.
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hex_password = hex::encode(hasher.finalize());

        // Config resolves effective SNI: explicit sni if set, else server hostname.
        let effective_sni = if sni.is_empty() {
            server.to_string()
        } else {
            sni.to_string()
        };

        let tls_config = TlsConfig {
            skip_cert_verify: skip_verify,
            ..TlsConfig::new(effective_sni)
        };

        let tls_layer = TlsLayer::new(&tls_config)
            .expect("TrojanAdapter: failed to build TlsLayer — check SNI/cert config");

        Self {
            name: SmolStr::from(name),
            server: SmolStr::from(server),
            port,
            addr_str: SmolStr::from(format!("{server}:{port}")),
            hex_password: SmolStr::from(hex_password),
            dialer,
            support_udp: udp,
            health: ProxyHealth::new(),
            tls_layer: Arc::new(tls_layer),
            #[cfg(feature = "mux")]
            mux: None,
        }
    }

    /// Enable sing-mux compatible connection multiplexing.  The Trojan
    /// request header on the shared connection targets the reserved mux
    /// destination (\`sp.mux.sing-box.arpa:444\`); the server switches the
    /// connection into mux mode on seeing it.
    #[cfg(feature = "mux")]
    pub fn with_mux(mut self, options: MuxOptions) -> Self {
        use crate::mux::{MUX_DESTINATION_FQDN, MUX_DESTINATION_PORT};

        let server = self.server.clone();
        let port = self.port;
        let hex_password = self.hex_password.clone();
        let tls_layer = Arc::clone(&self.tls_layer);
        let dialer = Arc::clone(&self.dialer);

        let dial: crate::mux::DialFn = Arc::new(move || {
            let server = server.clone();
            let hex_password = hex_password.clone();
            let tls_layer = Arc::clone(&tls_layer);
            let dialer = Arc::clone(&dialer);
            Box::pin(async move {
                // Build the mux-destination request header.
                let mut hdr_buf = [0u8; TROJAN_HEADER_BUF_SIZE];
                let pw = hex_password.as_bytes();
                let mut pos = 0;
                hdr_buf[..pw.len()].copy_from_slice(pw);
                pos += pw.len();
                hdr_buf[pos..pos + 2].copy_from_slice(b"\r\n");
                pos += 2;
                hdr_buf[pos] = CMD_CONNECT;
                pos += 1;
                hdr_buf[pos] = ATYP_DOMAIN;
                pos += 1;
                let fqdn = MUX_DESTINATION_FQDN.as_bytes();
                hdr_buf[pos] = u8::try_from(fqdn.len()).expect("static mux fqdn fits u8");
                pos += 1;
                hdr_buf[pos..pos + fqdn.len()].copy_from_slice(fqdn);
                pos += fqdn.len();
                hdr_buf[pos..pos + 2].copy_from_slice(&MUX_DESTINATION_PORT.to_be_bytes());
                pos += 2;
                hdr_buf[pos..pos + 2].copy_from_slice(b"\r\n");
                pos += 2;
                let header = &hdr_buf[..pos];

                let tcp = dialer.dial(&server, port).await.map_err(MeowError::Io)?;
                let mut stream = tls_layer
                    .connect(tcp)
                    .await
                    .map_err(transport_to_proxy_err)?;
                stream.write_all(header).await.map_err(MeowError::Io)?;
                Ok(Box::new(StreamConn(stream)) as Box<dyn ProxyConn>)
            })
        });
        self.mux = Some(MuxClient::new(dial, options));
        self
    }

    fn build_header<'a>(
        &self,
        metadata: &Metadata,
        cmd: u8,
        out: &'a mut [u8; TROJAN_HEADER_BUF_SIZE],
    ) -> Result<&'a [u8]> {
        let pw = self.hex_password.as_bytes();
        let mut pos = 0;
        out[..pw.len()].copy_from_slice(pw);
        pos += pw.len();
        out[pos..pos + 2].copy_from_slice(b"\r\n");
        pos += 2;
        out[pos] = cmd;
        pos += 1;
        pos = encode_socks5_addr_from_metadata_buf(out, pos, metadata)?;
        out[pos..pos + 2].copy_from_slice(b"\r\n");
        pos += 2;
        Ok(&out[..pos])
    }

    /// Open a TLS stream and write the Trojan request header.
    async fn open_tls_with_header(
        &self,
        metadata: &Metadata,
        cmd: u8,
    ) -> Result<Box<dyn TransportStream>> {
        let tcp = self
            .dialer
            .dial(&self.server, self.port)
            .await
            .map_err(MeowError::Io)?;
        self.tls_header_over(tcp, metadata, cmd).await
    }

    /// TLS-wrap `stream` and write the Trojan request header targeting
    /// `metadata`.  `stream` must already terminate at this Trojan server —
    /// `dial_tcp`/`dial_udp` obtain it from `dialer.dial`, `connect_over`
    /// receives it from the relay chain.
    async fn tls_header_over(
        &self,
        stream: Box<dyn TransportStream>,
        metadata: &Metadata,
        cmd: u8,
    ) -> Result<Box<dyn TransportStream>> {
        let mut hdr_buf = [0u8; TROJAN_HEADER_BUF_SIZE];
        let header = self.build_header(metadata, cmd, &mut hdr_buf)?;

        let mut stream = self
            .tls_layer
            .connect(stream)
            .await
            .map_err(transport_to_proxy_err)?;

        stream.write_all(header).await.map_err(MeowError::Io)?;
        Ok(stream)
    }
}

fn encode_socks5_addr_from_metadata_buf(
    buf: &mut [u8; TROJAN_HEADER_BUF_SIZE],
    mut pos: usize,
    metadata: &Metadata,
) -> Result<usize> {
    if !metadata.host.is_empty() {
        let host_bytes = metadata.host.as_bytes();
        if host_bytes.len() > MAX_DOMAIN_LEN {
            return Err(MeowError::Proxy(format!(
                "trojan: domain name too long ({} > {})",
                host_bytes.len(),
                MAX_DOMAIN_LEN
            )));
        }
        buf[pos] = ATYP_DOMAIN;
        pos += 1;
        buf[pos] = u8::try_from(host_bytes.len()).expect("domain length checked above");
        pos += 1;
        buf[pos..pos + host_bytes.len()].copy_from_slice(host_bytes);
        pos += host_bytes.len();
    } else if let Some(ip) = metadata.dst_ip {
        match ip {
            IpAddr::V4(v4) => {
                buf[pos] = ATYP_IPV4;
                pos += 1;
                buf[pos..pos + 4].copy_from_slice(&v4.octets());
                pos += 4;
            }
            IpAddr::V6(v6) => {
                buf[pos] = ATYP_IPV6;
                pos += 1;
                buf[pos..pos + 16].copy_from_slice(&v6.octets());
                pos += 16;
            }
        }
    } else {
        buf[pos] = ATYP_IPV4;
        pos += 1;
        buf[pos..pos + 4].copy_from_slice(&[0, 0, 0, 0]);
        pos += 4;
    }
    let port_bytes = metadata.dst_port.to_be_bytes();
    buf[pos..pos + 2].copy_from_slice(&port_bytes);
    Ok(pos + 2)
}

#[cfg(test)]
fn encode_socks5_addr_from_metadata(buf: &mut Vec<u8>, metadata: &Metadata) {
    if !metadata.host.is_empty() {
        buf.push(ATYP_DOMAIN);
        let host_bytes = metadata.host.as_bytes();
        buf.push(u8::try_from(host_bytes.len()).expect("test domain length must fit u8"));
        buf.extend_from_slice(host_bytes);
    } else if let Some(ip) = metadata.dst_ip {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        // No address at all — encode 0.0.0.0 as a placeholder; the Trojan
        // UDP_ASSOCIATE header destination is informational anyway.
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&[0, 0, 0, 0]);
    }
    buf.extend_from_slice(&metadata.dst_port.to_be_bytes());
}

/// Encode an explicit `SocketAddr` as a SOCKS5 address (used for per-packet
/// UDP frames where each datagram targets an arbitrary peer).
fn encode_socks5_addr_socket(buf: &mut Vec<u8>, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// Read a SOCKS5 address (ATYP + ADDR + PORT) and return it as a `SocketAddr`.
///
/// Domain-form replies are best-effort: if the domain parses as a literal IP
/// it's returned as such, otherwise we synthesize `0.0.0.0:<port>` and let
/// the caller log the original peer.  Trojan servers replying to client UDP
/// almost always echo the IP form anyway.
async fn read_socks5_addr<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await.map_err(MeowError::Io)?;
    Ok(match atyp[0] {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await.map_err(MeowError::Io)?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.map_err(MeowError::Io)?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await.map_err(MeowError::Io)?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.map_err(MeowError::Io)?;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes(port))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await.map_err(MeowError::Io)?;
            let mut domain = vec![0u8; len[0] as usize];
            reader
                .read_exact(&mut domain)
                .await
                .map_err(MeowError::Io)?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.map_err(MeowError::Io)?;
            let port = u16::from_be_bytes(port);
            let domain_str = std::str::from_utf8(&domain)
                .map_err(|e| MeowError::Proxy(format!("trojan udp: bad domain utf8: {e}")))?;
            // Try IP-literal first; otherwise fall back to UNSPECIFIED so the
            // tunnel still has a usable SocketAddr without a DNS round-trip.
            if let Ok(ip) = domain_str.parse::<IpAddr>() {
                SocketAddr::new(ip, port)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        }
        other => {
            return Err(MeowError::Proxy(format!(
                "trojan udp: unknown ATYP {other:#x}"
            )))
        }
    })
}

/// UDP-over-TLS packet connection.
///
/// The TLS stream is split into independent halves so `read_packet` and
/// `write_packet` can run concurrently from `&self`.  Each half is guarded
/// by its own `Mutex` because the trait exposes only `&self`, but in
/// practice the tunnel calls each direction from a dedicated task.
///
/// `read_packet` consumes frame bytes incrementally and `write_packet`
/// emits a frame with a single `write_all`. If either future is dropped
/// mid-frame (timeout, session teardown), the consumed read bytes are gone
/// and a partially written frame has already reached the wire — the next
/// operation would resume/append mid-frame, silently desyncing every
/// subsequent packet in BOTH directions (issue #514). Any such incomplete
/// frame poisons the conn: later reads and writes fail fast so the tunnel
/// tears the session down and re-dials instead of parsing or feeding
/// garbage.
pub struct TrojanPacketConn {
    reader: Mutex<ReadHalf<Box<dyn TransportStream>>>,
    writer: Mutex<WriteHalf<Box<dyn TransportStream>>>,
    poisoned: std::sync::atomic::AtomicBool,
}

impl TrojanPacketConn {
    fn new(stream: Box<dyn TransportStream>) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl ProxyPacketConn for TrojanPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        crate::check_not_desynced(&self.poisoned)?;
        let mut reader = self.reader.lock().await;
        // Re-check after the lock: a read parked here while another op was
        // cancelled mid-frame passed the outer check before the poison
        // store landed (issue #514 review).
        crate::check_not_desynced(&self.poisoned)?;
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);

        let addr = read_socks5_addr(&mut *reader).await?;

        let mut len_bytes = [0u8; 2];
        reader
            .read_exact(&mut len_bytes)
            .await
            .map_err(MeowError::Io)?;
        let length = u16::from_be_bytes(len_bytes) as usize;

        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await.map_err(MeowError::Io)?;
        if &crlf != b"\r\n" {
            return Err(MeowError::Proxy(format!(
                "trojan udp: expected CRLF, got {crlf:?}"
            )));
        }

        // Read the payload into the caller's buffer; if the frame is larger
        // than `buf`, drain the remainder so the next frame stays aligned.
        let to_copy = length.min(buf.len());
        if to_copy > 0 {
            reader
                .read_exact(&mut buf[..to_copy])
                .await
                .map_err(MeowError::Io)?;
        }
        if length > to_copy {
            let mut sink = vec![0u8; length - to_copy];
            reader.read_exact(&mut sink).await.map_err(MeowError::Io)?;
        }
        guard.complete = true;
        Ok((to_copy, addr))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        crate::check_not_desynced(&self.poisoned)?;
        if buf.len() > u16::MAX as usize {
            return Err(MeowError::Proxy(format!(
                "trojan udp: packet too large ({} > {})",
                buf.len(),
                u16::MAX
            )));
        }

        // Pre-size: ATYP(1) + addr(≤16) + port(2) + len(2) + CRLF(2) + payload.
        let mut frame = Vec::with_capacity(buf.len() + 23);
        encode_socks5_addr_socket(&mut frame, addr);
        frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(buf);

        let mut writer = self.writer.lock().await;
        // Same post-lock re-check as the read side: a write parked behind
        // one cancelled mid-frame must not append after a torn frame.
        crate::check_not_desynced(&self.poisoned)?;
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);
        writer.write_all(&frame).await.map_err(MeowError::Io)?;
        // The frame is fully buffered once `write_all` returns; a cancelled
        // `flush` cannot tear framing, so it runs unguarded.
        guard.complete = true;
        writer.flush().await.map_err(MeowError::Io)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // The tunnel only reads this for diagnostics — we have no real local
        // UDP socket bound, the datagrams ride on a TLS stream.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for TrojanAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Trojan
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        // With mux enabled, UDP rides the mux TCP session (unless
        // `only-tcp` forces the plain path) — mirrors mihomo's
        // SingMux.SupportUDP.
        self.support_udp || {
            #[cfg(feature = "mux")]
            {
                self.mux.as_ref().is_some_and(|mux| mux.supports_udp())
            }
            #[cfg(not(feature = "mux"))]
            {
                false
            }
        }
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "Trojan connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );
        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            let conn = mux.open_stream_for(metadata, "trojan").await?;
            return Ok(Box::new(conn));
        }
        let stream = self.open_tls_with_header(metadata, CMD_CONNECT).await?;
        Ok(Box::new(StreamConn(stream)))
    }

    /// Run TLS + the Trojan request header over an existing stream (relay
    /// chain).  Mux pooling is bypassed — the relay-supplied stream is
    /// single-use and cannot be re-dialled.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        #[cfg(feature = "mux")]
        if self.mux.is_some() {
            debug!("Trojan mux bypassed on relay-supplied stream (single-use)");
        }
        let stream = self
            .tls_header_over(Box::new(stream), metadata, CMD_CONNECT)
            .await?;
        Ok(Box::new(StreamConn(stream)))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        // Mux UDP rides the mux TCP session and does not depend on the
        // node's `udp:` flag — check it before the plain-path gate.
        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            if mux.supports_udp() {
                debug!(
                    "Trojan mux UDP connecting to {} via {}",
                    metadata.remote_address(),
                    self.addr_str
                );
            }
            if let Some(conn) = mux.open_packet_stream_for(metadata, "trojan").await? {
                return Ok(conn);
            }
        }
        if !self.support_udp {
            return Err(MeowError::NotSupported(
                "Trojan UDP is disabled for this proxy (set `udp: true`)".into(),
            ));
        }
        debug!(
            "Trojan UDP-associating for {} via {}",
            metadata.remote_address(),
            self.addr_str
        );
        let stream = self
            .open_tls_with_header(metadata, CMD_UDP_ASSOCIATE)
            .await?;
        Ok(Box::new(TrojanPacketConn::new(stream)))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_packet_handles_coalesced_frames() {
        use tokio::io::AsyncWriteExt;
        // QUIC first flight: server sends ~3 datagrams that coalesce into one
        // TLS record → meow must yield all three, not just the first.
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let conn = TrojanPacketConn::new(Box::new(client));

        let src: SocketAddr = "9.9.9.9:443".parse().unwrap();
        let payloads: [&[u8]; 3] = [b"\xc0one", b"\xc0two", b"\xc0three!"];
        let mut wire = Vec::new();
        for p in &payloads {
            encode_socks5_addr_socket(&mut wire, &src);
            wire.extend_from_slice(&(p.len() as u16).to_be_bytes());
            wire.extend_from_slice(b"\r\n");
            wire.extend_from_slice(p);
        }
        server.write_all(&wire).await.unwrap(); // one write → coalesced
        server.flush().await.unwrap();

        for expect in &payloads {
            let mut buf = [0u8; 2048];
            let (n, addr) = conn.read_packet(&mut buf).await.unwrap();
            assert_eq!(addr, src);
            assert_eq!(&buf[..n], *expect, "frame mismatch / dropped frame");
        }
    }

    /// Issue #514: cancelling `read_packet` mid-frame consumes an unknown
    /// number of bytes — resuming would parse payload bytes as a header.
    /// The conn must poison itself so the tunnel re-dials instead.
    #[tokio::test]
    async fn cancelled_read_poisons_packet_conn() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let conn = TrojanPacketConn::new(Box::new(client));
        let mut buf = [0u8; 2048];

        // Peer sends a partial header then stalls: ATYP + one address byte.
        server.write_all(&[ATYP_IPV4, 9, 9]).await.unwrap();
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.read_packet(&mut buf),
        )
        .await;
        assert!(cancelled.is_err(), "read must have timed out mid-header");

        // The peer then completes the frame — but the conn must not try to
        // resume mid-stream.
        server
            .write_all(&[9, 9, 0x01, 0xbb, 0, 1, b'\r', b'\n', b'x'])
            .await
            .unwrap();
        let err = conn.read_packet(&mut buf).await.unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "expected desync error after cancelled read, got {err:?}"
        );
    }

    /// The same poison must fire on a parse error after bytes were consumed
    /// (bad CRLF) — not only on future cancellation.
    #[tokio::test]
    async fn errored_read_poisons_packet_conn() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let conn = TrojanPacketConn::new(Box::new(client));
        let mut buf = [0u8; 2048];

        // Valid addr + length, then a wrong CRLF marker.
        let mut wire = Vec::new();
        encode_socks5_addr_socket(&mut wire, &"9.9.9.9:443".parse().unwrap());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(b"XX");
        wire.extend_from_slice(b"z");
        server.write_all(&wire).await.unwrap();

        let err = conn.read_packet(&mut buf).await.unwrap_err();
        assert!(err.to_string().contains("CRLF"), "got {err:?}");

        let err = conn.read_packet(&mut buf).await.unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "second read must fail fast on poisoned conn, got {err:?}"
        );
    }

    /// Happy-path guard: a completed frame read must not poison the conn.
    #[tokio::test]
    async fn completed_read_leaves_conn_usable() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let conn = TrojanPacketConn::new(Box::new(client));
        let mut buf = [0u8; 2048];
        let src: SocketAddr = "9.9.9.9:443".parse().unwrap();

        for i in 0u8..2 {
            let payload = [i, i, i];
            let mut wire = Vec::new();
            encode_socks5_addr_socket(&mut wire, &src);
            wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(b"\r\n");
            wire.extend_from_slice(&payload);
            server.write_all(&wire).await.unwrap();
            let (n, addr) = conn.read_packet(&mut buf).await.unwrap();
            assert_eq!(addr, src);
            assert_eq!(&buf[..n], &payload);
        }
    }

    /// Issue #514 review: a `write_packet` future cancelled mid-`write_all`
    /// has already pushed a frame PREFIX onto the wire — the peer reads
    /// `len` payload bytes from the next frame's header and the stream is
    /// desynced on the uplink direction, which the read-side poison cannot
    /// observe. The write path must poison the conn symmetrically.
    #[tokio::test]
    async fn cancelled_write_poisons_packet_conn() {
        // Tiny pipe: a 4 KiB datagram exceeds the buffer, so `write_all`
        // pends mid-frame with a prefix already on the wire.
        let (client, server) = tokio::io::duplex(1024);
        let conn = TrojanPacketConn::new(Box::new(client));
        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.write_packet(&[0xAA; 4096], &dst),
        )
        .await;
        assert!(cancelled.is_err(), "write must have timed out mid-frame");
        drop(server);

        let err = conn.write_packet(b"x", &dst).await.unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "write after a cancelled write must fail fast, got {err:?}"
        );
        let mut buf = [0u8; 64];
        let err = conn.read_packet(&mut buf).await.unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "read after a cancelled write must fail fast, got {err:?}"
        );
    }

    /// A write parked on the writer mutex while another write is cancelled
    /// mid-frame must fail fast instead of appending after the torn frame.
    #[tokio::test]
    async fn queued_write_after_cancelled_write_fails_fast() {
        let (client, server) = tokio::io::duplex(1024);
        let conn = std::sync::Arc::new(TrojanPacketConn::new(Box::new(client)));
        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

        // Occupy the writer mid-frame.
        let conn2 = std::sync::Arc::clone(&conn);
        let first = tokio::spawn(async move { conn2.write_packet(&[0xAA; 4096], &dst).await });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        // Queue a second write behind it, then abort the first mid-frame.
        let conn3 = std::sync::Arc::clone(&conn);
        let queued = tokio::spawn(async move { conn3.write_packet(b"queued", &dst).await });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        first.abort();
        let err = queued.await.unwrap().unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "queued write must fail fast after the poisoned first write, got {err:?}"
        );
        drop(server);
    }

    #[test]
    fn encode_socket_v4() {
        let mut buf = Vec::new();
        encode_socks5_addr_socket(&mut buf, &"127.0.0.1:53".parse().unwrap());
        assert_eq!(buf, vec![ATYP_IPV4, 127, 0, 0, 1, 0, 53]);
    }

    #[test]
    fn encode_socket_v6() {
        let mut buf = Vec::new();
        encode_socks5_addr_socket(&mut buf, &"[::1]:1234".parse().unwrap());
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);
        assert_eq!(&buf[buf.len() - 2..], &1234u16.to_be_bytes());
    }

    #[test]
    fn encode_metadata_domain_takes_precedence() {
        let mut buf = Vec::new();
        let md = Metadata {
            host: "example.com".into(),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: 443,
            ..Default::default()
        };
        encode_socks5_addr_from_metadata(&mut buf, &md);
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1] as usize, "example.com".len());
        assert_eq!(&buf[2..2 + "example.com".len()], b"example.com");
    }

    #[test]
    fn build_header_accepts_max_length_domain() {
        let adapter = TrojanAdapter::new(
            "t",
            "127.0.0.1",
            443,
            "secret",
            "example.com",
            true,
            false,
            std::sync::Arc::new(crate::dialer::DirectDialer),
        );
        let md = Metadata {
            host: "a".repeat(MAX_DOMAIN_LEN).into(),
            dst_port: 443,
            ..Default::default()
        };
        let mut buf = [0u8; TROJAN_HEADER_BUF_SIZE];
        let header = adapter
            .build_header(&md, CMD_CONNECT, &mut buf)
            .expect("255-byte domain should fit");

        assert_eq!(header.len(), TROJAN_HEADER_BUF_SIZE);
        assert_eq!(header[59], ATYP_DOMAIN);
        assert_eq!(header[60] as usize, MAX_DOMAIN_LEN);
    }

    #[test]
    fn build_header_rejects_overlong_domain_without_panic() {
        let adapter = TrojanAdapter::new(
            "t",
            "127.0.0.1",
            443,
            "secret",
            "example.com",
            true,
            false,
            std::sync::Arc::new(crate::dialer::DirectDialer),
        );
        let md = Metadata {
            host: "a".repeat(MAX_DOMAIN_LEN + 1).into(),
            dst_port: 443,
            ..Default::default()
        };
        let mut buf = [0u8; TROJAN_HEADER_BUF_SIZE];
        let err = adapter
            .build_header(&md, CMD_CONNECT, &mut buf)
            .expect_err("256-byte domain must error");

        assert!(
            matches!(err, MeowError::Proxy(ref msg) if msg.contains("domain name too long")),
            "expected domain length proxy error, got {err:?}"
        );
    }
}
