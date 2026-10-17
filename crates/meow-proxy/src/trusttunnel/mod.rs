//! TrustTunnel client outbound, over HTTP/2 or (opt-in, `quic: true`)
//! HTTP/3. The H2 transport's TLS and outbound sockets use the workspace
//! transport and dialer; the wire protocol is kept private.

mod protocol;
use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_transport::{
    tls::{ConnectTypedError, TlsConfig, TlsLayer},
    TransportError,
};
use protocol::{Client, H2Connector, IoStream, StreamConnector, UdpAssociation};
pub use protocol::{ExtraHeaders, Options};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Which transport carries the CONNECTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// HTTP/2 over TLS (PROTOCOL.md §3.1).
    H2,
    /// HTTP/3 over QUIC (PROTOCOL.md §3.2).
    #[cfg(feature = "trusttunnel-h3")]
    H3,
}

/// BoringSSL's certificate verification result. No peer-provided text,
/// credentials, or transport failure is presented as a certificate error.
#[derive(Debug)]
pub struct CertificateVerificationError {
    code: i32,
}
impl CertificateVerificationError {
    pub fn code(&self) -> i32 {
        self.code
    }
}
impl std::fmt::Display for CertificateVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TrustTunnel certificate verification failed (X509 code {})",
            self.code
        )
    }
}
impl std::error::Error for CertificateVerificationError {}

struct TlsConnector {
    server: String,
    port: u16,
    tls: TlsLayer,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
}
#[async_trait]
impl StreamConnector for TlsConnector {
    async fn connect(&self) -> io::Result<Box<dyn IoStream>> {
        // Shared sessions serve user streams even when housekeeping opens
        // them first. Mark the physical dial as user use, like other mux
        // adapters, so lazy front groups stay active during session reuse.
        let stream = self.dialer.dial(&self.server, self.port, false).await?;
        let tls = self
            .tls
            .connect_typed(stream)
            .await
            .map_err(|error| match error {
                ConnectTypedError::Transport(TransportError::Io(error)) => error,
                ConnectTypedError::Handshake(error) => {
                    let verification = error
                        .ssl()
                        .filter(|ssl| ssl.peer_certificate().is_some())
                        .and_then(|ssl| ssl.verify_result().err());
                    if let Some(verification) = verification {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            CertificateVerificationError {
                                code: verification.as_raw(),
                            },
                        )
                    } else if let Some(io) = error.as_io_error() {
                        io.raw_os_error().map_or_else(
                            || io::Error::new(io.kind(), "TrustTunnel TLS handshake failed"),
                            io::Error::from_raw_os_error,
                        )
                    } else {
                        io::Error::other("TrustTunnel TLS handshake failed")
                    }
                }
                _ => io::Error::other("TrustTunnel TLS setup failed"),
            })?;
        if tls.ssl().selected_alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TrustTunnel endpoint did not negotiate h2",
            ));
        }
        Ok(Box::new(tls))
    }
}

pub struct TrustTunnelAdapter {
    name: String,
    addr: String,
    client: Client,
    udp: bool,
    health: ProxyHealth,
}
impl TrustTunnelAdapter {
    #[allow(
        clippy::too_many_arguments,
        reason = "Matches the protocol adapter constructor convention; pool settings are grouped in Options"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        tls: TlsConfig,
        options: Options,
        udp: bool,
        transport: Transport,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Result<Self> {
        let connector = match transport {
            Transport::H2 => Self::h2_connector(server, port, tls, dialer)?,
            #[cfg(feature = "trusttunnel-h3")]
            Transport::H3 => Arc::new(protocol::QuicConnector::new(
                server,
                port,
                &tls,
                options.timeout,
            )?) as Arc<dyn protocol::Connector>,
        };
        let client = Client::new(connector, options)?;
        Ok(Self {
            name: name.into(),
            addr: if matches!(server.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
                format!("[{server}]:{port}")
            } else {
                format!("{server}:{port}")
            },
            client,
            udp,
            health: ProxyHealth::new(),
        })
    }

    fn h2_connector(
        server: &str,
        port: u16,
        mut tls: TlsConfig,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Result<Arc<dyn protocol::Connector>> {
        tls.alpn = vec!["h2".into()];
        tls.min_version = Some(meow_transport::tls::TlsVersion::Tls12);
        let tls = TlsLayer::new(&tls).map_err(|e| MeowError::Config(e.to_string()))?;
        Ok(Arc::new(H2Connector::new(Arc::new(TlsConnector {
            server: server.into(),
            port,
            tls,
            dialer,
        }))))
    }
}

fn protocol_error(error: io::Error) -> MeowError {
    if error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<protocol::AuthenticationFailed>)
    {
        MeowError::ProxyAuthFailed
    } else {
        MeowError::Io(error)
    }
}
#[async_trait]
impl ProxyAdapter for TrustTunnelAdapter {
    fn name(&self) -> &str {
        &self.name
    }
    fn addr(&self) -> &str {
        &self.addr
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::TrustTunnel
    }
    fn support_udp(&self) -> bool {
        self.udp
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
    fn reset_sessions(&self) {
        self.client.reset();
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let stream = self
            .client
            .tcp(&metadata.remote_address().to_string())
            .await
            .map_err(protocol_error)?;
        Ok(Box::new(crate::StreamConn(Box::new(stream))))
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.udp {
            return Err(MeowError::UdpNotSupported);
        }
        if metadata.domain_udp_target().is_some() {
            return Err(MeowError::NotSupported(
                "TrustTunnel UDP requires a resolved destination".into(),
            ));
        }
        // No source tuple is passed down on purpose: the association mints
        // its own, so the client's real address never reaches the endpoint.
        Ok(Box::new(PacketConn(
            self.client.udp().await.map_err(protocol_error)?,
        )))
    }
}
struct PacketConn(UdpAssociation);
#[async_trait]
impl ProxyPacketConn for PacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.0.recv_from(buffer).await.map_err(protocol_error)
    }
    async fn write_packet(&self, payload: &[u8], destination: &SocketAddr) -> Result<usize> {
        self.0
            .send_to(payload, *destination)
            .await
            .map_err(protocol_error)
    }
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.0.local_addr())
    }
    fn close(&self) -> Result<()> {
        self.0.close();
        Ok(())
    }
}
