//! TrustTunnel HTTP/2 client outbound. TLS and outbound sockets use the
//! workspace transport and dialer; the wire protocol is kept private.

mod protocol;
use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_transport::tls::{TlsConfig, TlsLayer};
pub use protocol::Options;
use protocol::{Client, Connector, IoStream, UdpAssociation};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

struct TlsConnector {
    server: String,
    port: u16,
    tls: TlsLayer,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
}
#[async_trait]
impl Connector for TlsConnector {
    async fn connect(&self, internal: bool) -> io::Result<Box<dyn IoStream>> {
        let stream = self.dialer.dial(&self.server, self.port, internal).await?;
        let tls = self.tls.connect_typed(stream).await.map_err(|_| {
            io::Error::other("TrustTunnel TLS handshake or certificate verification failed")
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
        mut tls: TlsConfig,
        options: Options,
        udp: bool,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Result<Self> {
        tls.alpn = vec!["h2".into()];
        tls.min_version = Some(meow_transport::tls::TlsVersion::Tls12);
        let tls = TlsLayer::new(&tls).map_err(|e| MeowError::Config(e.to_string()))?;
        let client = Client::new(
            Arc::new(TlsConnector {
                server: server.into(),
                port,
                tls,
                dialer,
            }),
            options,
        )?;
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
}

fn protocol_error(error: io::Error) -> MeowError {
    if error.kind() == io::ErrorKind::PermissionDenied
        && error.to_string() == "TrustTunnel authentication failed"
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
            .tcp_with_context(
                &metadata.remote_address().to_string(),
                metadata.is_internal(),
            )
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
        let source = SocketAddr::new(
            metadata.src_ip.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
            metadata.src_port,
        );
        Ok(Box::new(PacketConn(
            self.client
                .udp_with_context(source, &metadata.process, metadata.is_internal())
                .await
                .map_err(protocol_error)?,
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
