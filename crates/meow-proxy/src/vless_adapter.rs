//! VLESS outbound proxy adapter (M1.B-2).
//!
//! Implements `VlessAdapter: ProxyAdapter` — plain VLESS with optional
//! XTLS-Vision splice (`flow: xtls-rprx-vision`, behind `vless-vision` feature).
//!
//! Transport chain (TLS → WS → …) is built by the config parser via
//! `VlessAdapter::new()` and applied in `dial_tcp` / `dial_udp` before the VLESS
//! header exchange.
//!
//! # Feature flags
//!
//! - `vless` — this module + plain `VlessAdapter` (no Vision).
//! - `vless-vision` — adds `VisionConn` and the `VlessFlow::XtlsRprxVision` dial path.
//!
//! # Wire format
//!
//! See `vless/header.rs` for the complete byte-level specification.

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use smol_str::SmolStr;
use tracing::debug;

#[cfg(feature = "mux")]
use crate::mux::{MuxClient, MuxOptions};
use crate::stream_conn::StreamConn;
use crate::transport_chain::TransportChain;
use crate::vless::{addr_from_metadata, Cmd, VlessConn, VlessPacketConn};
use std::sync::Arc;

#[cfg(feature = "vless-vision")]
use crate::vless::VisionConn;

#[cfg(feature = "vless-encryption")]
use crate::vless::encryption::ClientInstance;

// ─── XTLS flow ────────────────────────────────────────────────────────────────

/// XTLS flow mode for VLESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessFlow {
    /// `flow: xtls-rprx-vision` — Vision TLS-splice mode.
    /// Requires `vless-vision` Cargo feature and an encrypting outer transport.
    XtlsRprxVision,
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

/// VLESS outbound proxy adapter.
pub struct VlessAdapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    addr_str: SmolStr,
    uuid_bytes: [u8; 16],
    flow: Option<VlessFlow>,
    udp: bool,
    transport: Arc<TransportChain>,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
    /// sing-mux compatible connection multiplexing (optional).
    #[cfg(feature = "mux")]
    mux: Option<Arc<MuxClient>>,
    /// VLESS post-quantum Encryption (`mlkem768x25519plus`), applied below the
    /// VLESS header exchange once per dial. `None` for plain VLESS.
    #[cfg(feature = "vless-encryption")]
    encryption: Option<Arc<ClientInstance>>,
    health: ProxyHealth,
}

impl VlessAdapter {
    /// Construct a `VlessAdapter`.
    ///
    /// `uuid_bytes` — 16-byte binary UUID.
    /// `transport`  — pre-built chain (TLS, WS, etc.).
    /// `flow`       — None for plain VLESS, Some(XtlsRprxVision) for Vision.
    #[allow(
        clippy::too_many_arguments,
        reason = "dialer param for pluggable TcpDialer"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        uuid_bytes: [u8; 16],
        flow: Option<VlessFlow>,
        udp: bool,
        transport: TransportChain,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            server: SmolStr::from(server),
            port,
            addr_str: SmolStr::from(format!("{server}:{port}")),
            uuid_bytes,
            flow,
            udp,
            transport: Arc::new(transport),
            dialer,
            #[cfg(feature = "mux")]
            mux: None,
            #[cfg(feature = "vless-encryption")]
            encryption: None,
            health: ProxyHealth::new(),
        }
    }

    /// Enable connection multiplexing.  Two wire protocols share one
    /// connection pool (protocol picked by the `protocol` mux option):
    ///
    /// * sing-mux (smux/yamux/h2mux) — the session's VLESS request targets
    ///   the reserved mux destination (sp.mux.sing-box.arpa:444) and a mux
    ///   request header follows; server must be sing-box / mihomo.
    /// * muxcool — the session's VLESS request itself is the signaling
    ///   (CommandMux 0x03, no address); server must be Xray / sing-box.
    #[cfg(feature = "mux")]
    pub fn with_mux(mut self, options: MuxOptions) -> Self {
        use crate::mux::{MuxClient, Protocol, MUX_DESTINATION_FQDN, MUX_DESTINATION_PORT};
        use crate::vless::header::VlessAddr;
        use std::sync::Arc as StdArc;

        let server = self.server.clone();
        let port = self.port;
        let uuid_bytes = self.uuid_bytes;
        let transport = StdArc::clone(&self.transport);
        let flow = self.flow;
        let dialer = Arc::clone(&self.dialer);
        let protocol = options.protocol;
        #[cfg(feature = "vless-encryption")]
        let encryption = self.encryption.clone();

        let dial: crate::mux::DialFn = StdArc::new(move || {
            let server = server.clone();
            let transport = StdArc::clone(&transport);
            let dialer = Arc::clone(&dialer);
            #[cfg(feature = "vless-encryption")]
            let encryption = encryption.clone();
            Box::pin(async move {
                let stream = dialer.dial(&server, port).await.map_err(MeowError::Io)?;
                let stream = transport.connect(stream).await?;
                #[cfg(feature = "vless-encryption")]
                let stream = match &encryption {
                    Some(encryption) => encryption.handshake(stream).await?,
                    None => stream,
                };
                let flow_str = match flow {
                    #[cfg(feature = "vless-vision")]
                    Some(VlessFlow::XtlsRprxVision) => Some("xtls-rprx-vision"),
                    _ => None,
                };
                match protocol {
                    Protocol::MuxCool => {
                        // Vision wraps before the header: the first mux
                        // frame (a stream's New frame) carries the VLESS
                        // CommandMux request inside the same Vision record.
                        #[cfg(feature = "vless-vision")]
                        if flow_str.is_some() {
                            let vless =
                                VlessConn::new_mux_deferred(stream, &uuid_bytes, flow_str).await?;
                            return Ok(
                                Box::new(VisionConn::new(vless, uuid_bytes)) as Box<dyn ProxyConn>
                            );
                        }
                        let conn = VlessConn::new_mux(stream, &uuid_bytes, flow_str).await?;
                        Ok(Box::new(StreamConn(Box::new(conn))) as Box<dyn ProxyConn>)
                    }
                    Protocol::Smux | Protocol::Yamux | Protocol::H2Mux => {
                        let addr =
                            VlessAddr::domain(MUX_DESTINATION_FQDN).expect("static mux fqdn");
                        #[cfg(feature = "vless-vision")]
                        // Defense-in-depth: parse_vless rejects vision+mux at
                        // config time; this guards programmatic construction.
                        // Match on flow_str (Some only for the Vision variant)
                        // rather than flow.is_some(), so a future second flow
                        // variant does not silently build a VisionConn.
                        if flow_str.is_some() {
                            let vless = VlessConn::new_deferred(
                                stream,
                                &uuid_bytes,
                                flow_str,
                                Cmd::Tcp,
                                MUX_DESTINATION_PORT,
                                &addr,
                            )
                            .await?;
                            return Ok(
                                Box::new(VisionConn::new(vless, uuid_bytes)) as Box<dyn ProxyConn>
                            );
                        }
                        let conn = VlessConn::new(
                            stream,
                            &uuid_bytes,
                            flow_str,
                            Cmd::Tcp,
                            MUX_DESTINATION_PORT,
                            &addr,
                        )
                        .await?;
                        Ok(Box::new(StreamConn(Box::new(conn))) as Box<dyn ProxyConn>)
                    }
                }
            })
        });
        self.mux = Some(MuxClient::new(dial, options));
        self
    }

    /// Attach a VLESS Encryption client (`encryption: mlkem768x25519plus…`).
    ///
    /// Shared across dials so the 0-RTT resumption ticket cache persists.
    #[cfg(feature = "vless-encryption")]
    pub fn set_encryption(&mut self, encryption: Option<Arc<ClientInstance>>) {
        self.encryption = encryption;
    }

    /// Dial a raw TCP + transport-chain stream to the VLESS server, then run the
    /// VLESS Encryption handshake if one is configured.
    async fn dial_stream(&self) -> Result<Box<dyn meow_transport::Stream>> {
        let stream = self
            .dialer
            .dial(&self.server, self.port)
            .await
            .map_err(MeowError::Io)?;
        self.wrap_stream(stream).await
    }

    /// Apply the configured transport chain (TLS → WS → …) and the VLESS
    /// Encryption handshake on top of `stream`.  `stream` must already
    /// terminate at this adapter's server — `dial_tcp` obtains it from
    /// `dialer.dial`, `connect_over` receives it from the relay chain.
    async fn wrap_stream(
        &self,
        stream: Box<dyn meow_transport::Stream>,
    ) -> Result<Box<dyn meow_transport::Stream>> {
        let stream = self.transport.connect(stream).await?;
        #[cfg(feature = "vless-encryption")]
        if let Some(encryption) = &self.encryption {
            return encryption.handshake(stream).await;
        }
        Ok(stream)
    }

    /// Run the VLESS request exchange targeting `metadata` on `stream`
    /// (already transport-wrapped).  Shared by `dial_tcp` and `connect_over`.
    async fn handshake_tcp(
        &self,
        stream: Box<dyn meow_transport::Stream>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let addr = addr_from_metadata(metadata);

        // Choose flow string for the request header addon.
        let flow_str = match self.flow {
            #[cfg(feature = "vless-vision")]
            Some(VlessFlow::XtlsRprxVision) => Some("xtls-rprx-vision"),
            None => None,
            #[cfg(not(feature = "vless-vision"))]
            Some(VlessFlow::XtlsRprxVision) => {
                return Err(MeowError::Config(
                    "vless: xtls-rprx-vision requires the `vless-vision` Cargo feature; \
                     rebuild with --features vless-vision"
                        .into(),
                ));
            }
        };

        let conn = match self.flow {
            // Vision must wrap the connection BEFORE the request header is
            // sent: xray expects the VLESS request inside the first
            // Vision-padded record (mihomo wires it the same way), so the
            // header is deferred to the first write through the Vision
            // layer.
            #[cfg(feature = "vless-vision")]
            Some(VlessFlow::XtlsRprxVision) => {
                let vless = VlessConn::new_deferred(
                    stream,
                    &self.uuid_bytes,
                    flow_str,
                    Cmd::Tcp,
                    metadata.dst_port,
                    &addr,
                )
                .await?;
                Box::new(VisionConn::new(vless, self.uuid_bytes)) as Box<dyn ProxyConn>
            }
            _ => {
                let conn = VlessConn::new(
                    stream,
                    &self.uuid_bytes,
                    flow_str,
                    Cmd::Tcp,
                    metadata.dst_port,
                    &addr,
                )
                .await?;
                Box::new(StreamConn(Box::new(conn)))
            }
        };
        Ok(conn)
    }
}

// ─── ProxyAdapter impl ────────────────────────────────────────────────────────

#[async_trait]
impl ProxyAdapter for VlessAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Vless
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
            "VLESS connecting to {} via {} flow={:?}",
            metadata.remote_address(),
            self.addr_str,
            self.flow
        );

        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            let conn = mux.open_stream_for(metadata, "vless").await?;
            return Ok(Box::new(conn));
        }

        let stream = self.dial_stream().await?;
        self.handshake_tcp(stream, metadata).await
    }

    /// Run the VLESS handshake over an existing stream (relay chain).
    ///
    /// The stream already terminates at this VLESS server, so the full
    /// transport chain (TLS/WS/Reality) and the VLESS Encryption handshake
    /// still apply — only the raw dial is skipped.  Mux pooling is bypassed:
    /// a relay-supplied stream is single-use and cannot be re-dialled.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        #[cfg(feature = "mux")]
        if self.mux.is_some() {
            debug!("VLESS mux bypassed on relay-supplied stream (single-use)");
        }
        let stream = self.wrap_stream(Box::new(stream)).await?;
        self.handshake_tcp(stream, metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            if mux.supports_udp() {
                debug!(
                    "VLESS mux UDP connecting to {} via {}",
                    metadata.remote_address(),
                    self.addr_str
                );
            }
            if let Some(conn) = mux.open_packet_stream_for(metadata, "vless").await? {
                return Ok(conn);
            }
        }

        // Vision is TCP-only; UDP always uses plain VlessConn regardless of flow.
        debug!(
            "VLESS UDP connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );

        let stream = self.dial_stream().await?;
        let addr = addr_from_metadata(metadata);

        let conn = VlessPacketConn::new(stream, &self.uuid_bytes, metadata.dst_port, &addr).await?;

        Ok(Box::new(conn))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── Crate invariants + struct tests (§E, §I) ────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::DirectDialer;
    use meow_common::AdapterType;

    fn make_adapter(flow: Option<VlessFlow>, udp: bool) -> VlessAdapter {
        VlessAdapter::new(
            "test-vless",
            "127.0.0.1",
            12345,
            [0u8; 16],
            flow,
            udp,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        )
    }

    // ─── I1: adapter_type() returns Vless ────────────────────────────────────

    #[test]
    fn vless_adapter_type_is_vless() {
        let a = make_adapter(None, false);
        assert_eq!(a.adapter_type(), AdapterType::Vless);
    }

    // ─── I2: support_udp false by default ────────────────────────────────────

    #[test]
    fn vless_support_udp_false_by_default() {
        let a = make_adapter(None, false);
        assert!(!a.support_udp());
    }

    // ─── I3: support_udp true when configured ────────────────────────────────

    #[test]
    fn vless_support_udp_true_when_configured() {
        let a = make_adapter(None, true);
        assert!(a.support_udp());
    }

    // ─── E1: TCP + no TLS → chain length 0 ───────────────────────────────────

    #[test]
    fn vless_tcp_no_tls_empty_chain() {
        let a = make_adapter(None, false);
        assert_eq!(a.transport.len(), 0, "no-TLS TCP chain must be empty");
    }

    // ─── E2: TCP + TLS → chain length 1 ──────────────────────────────────────

    #[test]
    fn vless_tcp_with_tls_chain() {
        use meow_transport::tls::{TlsConfig, TlsLayer};
        let mut chain = TransportChain::empty();
        let tls_cfg = TlsConfig::new("example.com");
        let tls_layer = TlsLayer::new(&tls_cfg).expect("TlsLayer");
        chain.push(Box::new(tls_layer));
        let a = VlessAdapter::new(
            "t",
            "127.0.0.1",
            1,
            [0u8; 16],
            None,
            false,
            chain,
            Arc::new(DirectDialer),
        );
        assert_eq!(a.transport.len(), 1, "TLS-only chain must have 1 layer");
    }

    // ─── E3: WS + TLS → chain length 2, TLS before WS ────────────────────────

    #[test]
    fn vless_ws_with_tls_chain_ordered() {
        use meow_transport::tls::{TlsConfig, TlsLayer};
        use meow_transport::ws::{WsConfig, WsLayer};
        let mut chain = TransportChain::empty();
        let tls_cfg = TlsConfig::new("example.com");
        chain.push(Box::new(TlsLayer::new(&tls_cfg).expect("TlsLayer")));
        chain.push(Box::new(
            WsLayer::new(WsConfig {
                host_header: Some("example.com".into()),
                ..WsConfig::default()
            })
            .expect("WsLayer::new"),
        ));
        let a = VlessAdapter::new(
            "t",
            "127.0.0.1",
            1,
            [0u8; 16],
            None,
            false,
            chain,
            Arc::new(DirectDialer),
        );
        assert_eq!(a.transport.len(), 2, "TLS+WS chain must have 2 layers");
    }

    // ─── E5: Vision flow dial_tcp returns VisionConn ─────────────────────────

    #[cfg(feature = "vless-vision")]
    #[test]
    fn vless_vision_wrapped_around_vless_conn() {
        // This is a compile-time check: if VlessFlow::XtlsRprxVision compiles
        // and the dial_tcp match arm for it compiles, the test passes.
        // (Runtime round-trip is in the integration test H4.)
        let _a = make_adapter(Some(VlessFlow::XtlsRprxVision), false);
    }

    // ─── E6: dial_udp ignores Vision flow (guard-rail) ───────────────────────

    // This is tested at runtime in the integration tests.
    // The compile-time check: dial_udp should always compile regardless of flow.
    #[test]
    fn vless_udp_ignores_vision_flow_compiles() {
        // Just verify the adapter compiles with XtlsRprxVision + udp: true.
        #[cfg(feature = "vless-vision")]
        let _ = make_adapter(Some(VlessFlow::XtlsRprxVision), true);
        let _ = make_adapter(None, true);
    }
}
