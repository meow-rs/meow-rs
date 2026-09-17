mod body;
mod conn;
pub mod header;
mod kdf;

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use smol_str::SmolStr;
use std::sync::Arc;
use tracing::debug;

use crate::transport_chain::TransportChain;
pub use header::Security;

pub struct VmessAdapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    addr_str: SmolStr,
    cmd_key: [u8; 16],
    security: Security,
    udp: bool,
    transport: Arc<TransportChain>,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
    health: ProxyHealth,
    /// sing-mux compatible connection multiplexing (optional).
    #[cfg(feature = "mux")]
    mux: Option<Arc<crate::mux::MuxClient>>,
}

impl VmessAdapter {
    #[allow(
        clippy::too_many_arguments,
        reason = "dialer param for pluggable TcpDialer"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        uuid_bytes: [u8; 16],
        security: Security,
        udp: bool,
        transport: TransportChain,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            server: SmolStr::from(server),
            port,
            addr_str: SmolStr::from(format!("{server}:{port}")),
            cmd_key: header::cmd_key(&uuid_bytes),
            security,
            udp,
            transport: Arc::new(transport),
            dialer,
            health: ProxyHealth::new(),
            #[cfg(feature = "mux")]
            mux: None,
        }
    }

    /// Enable connection multiplexing.  Two wire protocols share one
    /// connection pool (protocol picked by the `protocol` mux option):
    ///
    /// * sing-mux (smux/yamux/h2mux) — the session's VMess request targets
    ///   the reserved mux destination (sp.mux.sing-box.arpa:444) and a mux
    ///   request header follows; server must be sing-box / mihomo with
    ///   multiplex enabled on the VMess inbound.
    /// * muxcool — the session's VMess request itself is the signaling
    ///   (CommandMux 0x03, no address); server must be Xray, or sing-box /
    ///   mihomo (sing-vmess routes CommandMux to HandleMuxConnection, no
    ///   inbound config needed).
    #[cfg(feature = "mux")]
    pub fn with_mux(mut self, options: crate::mux::MuxOptions) -> Self {
        use crate::mux::{MuxClient, MUX_DESTINATION_FQDN, MUX_DESTINATION_PORT};
        use std::sync::Arc as StdArc;

        let transport = Arc::clone(&self.transport);
        let server = self.server.clone();
        let cmd_key = self.cmd_key;
        let security = self.security;
        let port = self.port;
        let protocol = options.protocol;
        let dialer = Arc::clone(&self.dialer);

        let dial: crate::mux::DialFn = StdArc::new(move || {
            let transport = Arc::clone(&transport);
            let server = server.clone();
            let dialer = Arc::clone(&dialer);
            Box::pin(async move {
                let sealed = match protocol {
                    crate::mux::Protocol::MuxCool => {
                        header::seal_mux_request_header(&cmd_key, security)
                    }
                    _ => {
                        let metadata = Metadata {
                            host: MUX_DESTINATION_FQDN.into(),
                            dst_port: MUX_DESTINATION_PORT,
                            ..Default::default()
                        };
                        header::seal_request_header(&cmd_key, security, &metadata, false)
                    }
                }
                .map_err(MeowError::Proxy)?;
                dial_vmess(&transport, &server, port, dialer.as_ref(), sealed, security).await
            })
        });
        self.mux = Some(MuxClient::new(dial, options));
        self
    }

    /// Dial a raw TCP + transport-chain stream to the VMess server, run the
    /// VMess request header exchange for the given destination, and return
    /// the encrypted duplex.
    async fn dial_to(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let sealed = header::seal_request_header(&self.cmd_key, self.security, metadata, false)
            .map_err(MeowError::Proxy)?;
        dial_vmess(
            &self.transport,
            &self.server,
            self.port,
            self.dialer.as_ref(),
            sealed,
            self.security,
        )
        .await
    }
}

/// Dial a raw TCP + transport-chain stream to the VMess server, run the
/// VMess request header exchange for the given destination, and return the
/// encrypted duplex.  Shared by the plain dial path and the sing-mux
/// session dialer (which targets the reserved mux destination).
async fn dial_vmess(
    transport: &TransportChain,
    server: &str,
    port: u16,
    dialer: &dyn crate::dialer::TcpDialer,
    sealed: header::SealedHeader,
    security: Security,
) -> Result<Box<dyn ProxyConn>> {
    let stream = dialer.dial(server, port).await.map_err(MeowError::Io)?;
    vmess_over(transport, stream, sealed, security).await
}

/// Apply the transport chain and run the VMess request exchange on
/// `stream`, which must already terminate at this adapter's server —
/// `dial_tcp` obtains it from `dialer.dial`, `connect_over` receives it
/// from the relay chain.
async fn vmess_over(
    transport: &TransportChain,
    stream: Box<dyn meow_transport::Stream>,
    sealed: header::SealedHeader,
    security: Security,
) -> Result<Box<dyn ProxyConn>> {
    use tokio::io::AsyncWriteExt;

    let mut stream = transport
        .connect(stream)
        .await
        .map_err(|e| MeowError::Proxy(format!("vmess transport: {e}")))?;

    stream
        .write_all(&sealed.bytes)
        .await
        .map_err(MeowError::Io)?;

    let read_cipher =
        body::BodyCipher::new(security, &sealed.req_key, &sealed.req_iv, sealed.resp_v);
    let write_cipher =
        body::BodyCipher::new(security, &sealed.req_key, &sealed.req_iv, sealed.resp_v);

    let duplex = conn::spawn_vmess_relay(
        stream,
        read_cipher,
        write_cipher,
        sealed.req_key,
        sealed.req_iv,
        sealed.resp_v,
    );
    Ok(Box::new(crate::stream_conn::StreamConn(Box::new(duplex))))
}

#[async_trait]
impl ProxyAdapter for VmessAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Vmess
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        // With mux enabled, UDP rides the mux TCP session (unless
        // `only-tcp` forces the plain path) — mirrors mihomo's
        // SingMux.SupportUDP.
        self.udp || {
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
            "VMess connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );

        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            let conn = mux.open_stream_for(metadata, "vmess").await?;
            return Ok(Box::new(conn));
        }

        self.dial_to(metadata).await
    }

    /// Run the transport chain + VMess request exchange over an existing
    /// stream (relay chain).  Mux pooling is bypassed — the relay-supplied
    /// stream is single-use and cannot be re-dialled.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        #[cfg(feature = "mux")]
        if self.mux.is_some() {
            debug!("VMess mux bypassed on relay-supplied stream (single-use)");
        }
        let sealed = header::seal_request_header(&self.cmd_key, self.security, metadata, false)
            .map_err(MeowError::Proxy)?;
        vmess_over(&self.transport, Box::new(stream), sealed, self.security).await
    }

    #[cfg_attr(not(feature = "mux"), allow(unused_variables))]
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            if mux.supports_udp() {
                debug!(
                    "VMess mux UDP connecting to {} via {}",
                    metadata.remote_address(),
                    self.addr_str
                );
            }
            if let Some(conn) = mux.open_packet_stream_for(metadata, "vmess").await? {
                return Ok(conn);
            }
        }

        Err(MeowError::NotSupported(
            "vmess UDP relay not yet implemented".into(),
        ))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::DirectDialer;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    /// Minimal AsyncRead+AsyncWrite+ProxyConn newtype over a duplex half —
    /// stands in for the relay chain's upstream leg. Same pattern as
    /// `mux::muxcool`'s TestConn.
    struct DuplexConn(DuplexStream);

    impl ProxyConn for DuplexConn {}

    impl AsyncRead for DuplexConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    /// `connect_over` must run the VMess request exchange on the supplied
    /// stream: the peer side sees a sealed AEAD header that opens to the
    /// requested destination — proving the relay path skipped only the raw
    /// socket dial, not the protocol handshake.
    #[tokio::test]
    async fn connect_over_writes_vmess_request_for_metadata() {
        const UUID: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let adapter = VmessAdapter::new(
            "vmess-relay-hop",
            "127.0.0.1",
            10086, // unused — connect_over never dials
            UUID,
            Security::Aes128Gcm,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let metadata = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let _conn = adapter
            .connect_over(Box::new(DuplexConn(client)), &metadata)
            .await
            .expect("connect_over must succeed over duplex");

        // Server side: read the fixed 42-byte prefix, derive the exact
        // frame length from its sealed length block, then read the rest —
        // the header must be consumed exactly, with nothing trailing.
        let mut prefix = [0u8; 42];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut prefix)
            .await
            .expect("sealed header prefix");
        let frame_len = header::tests::request_header_frame_len(&adapter.cmd_key, &prefix)
            .expect("sealed length block must open");
        let mut frame = prefix.to_vec();
        frame.resize(frame_len, 0);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut frame[42..]),
        )
        .await
        .expect("sealed payload must arrive")
        .expect("read");
        let pt = header::tests::server_open_request_header(&adapter.cmd_key, &frame)
            .expect("server must be able to open the sealed header");

        // Plaintext: ver(1)|req_iv(16)|req_key(16)|resp_v(1)|opt(1)|
        //            p+sec(1)|reserved(1)|cmd(1)|port(2)|atyp+addr|pad|fnv(4)
        assert_eq!(pt[37], 0x01, "cmd must be TCP CONNECT");
        let port = u16::from_be_bytes([pt[38], pt[39]]);
        assert_eq!(port, 443, "header must carry metadata.dst_port");
        assert_eq!(pt[40], 0x02, "host must encode as domain (atyp 0x02)");
        let dom_len = pt[41] as usize;
        assert_eq!(
            &pt[42..42 + dom_len],
            b"example.com",
            "header must carry metadata.host"
        );
    }

    /// `connect_over` must also carry the full duplex exchange, not just the
    /// request header: the peer answers the sealed response header, reads
    /// AEAD body records the client encrypts, and its encrypted reply
    /// records surface as plaintext on the returned conn.
    #[tokio::test]
    async fn connect_over_carries_full_duplex_vmess_exchange() {
        const UUID: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let adapter = VmessAdapter::new(
            "vmess-relay-hop",
            "127.0.0.1",
            10086,
            UUID,
            Security::Aes128Gcm,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let metadata = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let mut conn = adapter
            .connect_over(Box::new(DuplexConn(client)), &metadata)
            .await
            .expect("connect_over must succeed over duplex");

        // Server side: open the request header, extract the per-connection
        // key material, answer the response header, then echo body records.
        let server_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut prefix = [0u8; 42];
            server.read_exact(&mut prefix).await.expect("header prefix");
            let frame_len = header::tests::request_header_frame_len(&adapter.cmd_key, &prefix)
                .expect("sealed length block must open");
            let mut frame = prefix.to_vec();
            frame.resize(frame_len, 0);
            server
                .read_exact(&mut frame[42..])
                .await
                .expect("header payload");
            let pt = header::tests::server_open_request_header(&adapter.cmd_key, &frame)
                .expect("sealed request header must open");

            let req_iv: [u8; 16] = pt[1..17].try_into().unwrap();
            let req_key: [u8; 16] = pt[17..33].try_into().unwrap();
            let resp_v = pt[33];

            server
                .write_all(&header::tests::seal_response_header(
                    &req_key, &req_iv, resp_v,
                ))
                .await
                .expect("response header write");

            let mut cipher =
                body::BodyCipher::server_mirror(Security::Aes128Gcm, &req_key, &req_iv);
            while let Some(rec) = cipher
                .read_record(&mut server)
                .await
                .expect("body record must decrypt")
            {
                cipher
                    .write_record(&mut server, &rec)
                    .await
                    .expect("echo record must encrypt");
            }
        });

        // Client side: two plaintext ping-pongs through the record layer.
        for payload in [b"ping-one".as_slice(), b"ping-two-longer".as_slice()] {
            conn.write_all(payload).await.expect("write failed");
            conn.flush().await.expect("flush failed");
            let mut buf = vec![0u8; payload.len()];
            tokio::io::AsyncReadExt::read_exact(&mut conn, &mut buf)
                .await
                .expect("echo read failed");
            assert_eq!(&buf, payload, "duplex echo mismatch");
        }

        drop(conn);
        tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
            .await
            .expect("server echo task timed out")
            .expect("server echo task panicked");
    }
}
