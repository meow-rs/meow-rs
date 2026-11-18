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
use crate::mux::{DialFn, MuxClient, MuxOptions, Protocol};
use crate::stream_conn::StreamConn;
use crate::transport_chain::TransportChain;
use crate::vless::{addr_from_metadata, Cmd, VlessConn, VlessPacketConn};
use std::sync::Arc;
use std::time::Instant;

#[cfg(all(feature = "mux", feature = "vless-vision"))]
use std::sync::atomic::{AtomicBool, Ordering};

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

/// Per-call connect-phase timings of [`VlessAdapter::dial_stream`], in
/// milliseconds as `f64` (the measured phases are mostly sub-millisecond on
/// loopback rigs).  `dial_tcp` / `connect_over` report them as the
/// `vless connect breakdown` debug line.
#[derive(Debug, Default, Clone, Copy)]
struct DialPhases {
    /// `dialer.dial` — the direct TCP connect, or the front hop's whole
    /// dial on a `dialer-proxy` chain (its own transport handshake folds
    /// in here).
    tcp_ms: f64,
    /// `transport.connect(_shared)` plus the VLESS Encryption handshake —
    /// the BoringSSL handshake for a `tls: true` node.
    transport_ms: f64,
    /// The stream came off a multiplexed transport's shared conn: no dial
    /// or transport handshake ran, so the phases above read 0.
    reused: bool,
}

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
    /// Warn-once latch: a vision node falling back to a bare `Cmd::Udp`
    /// request (a domain UDP target Mux.Cool cannot express, or
    /// `only-tcp`) is rejected by strict servers as a flow mismatch —
    /// surface that once per adapter, not per association.
    #[cfg(all(feature = "mux", feature = "vless-vision"))]
    vision_udp_bare_warned: AtomicBool,
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
            #[cfg(all(feature = "mux", feature = "vless-vision"))]
            vision_udp_bare_warned: AtomicBool::new(false),
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
        self.mux = Some(MuxClient::new(self.mux_dial_fn(options.protocol), options));
        self
    }

    /// The session dial shared by the configured mux pool and by the
    /// per-association Mux.Cool session `dial_udp` builds for a vision
    /// node: `self.dialer` (so `dialer-proxy` chains still apply) →
    /// transport chain → Encryption handshake → VLESS request for
    /// `protocol` (smux/yamux/h2mux target `sp.mux.sing-box.arpa:444`
    /// with `Cmd::Tcp`; muxcool is the `Cmd::Mux` CommandMux request,
    /// Vision-wrapped first when a flow is set).
    #[cfg(feature = "mux")]
    fn mux_dial_fn(&self, protocol: Protocol) -> DialFn {
        use crate::mux::{MUX_DESTINATION_FQDN, MUX_DESTINATION_PORT};
        use crate::vless::header::VlessAddr;
        use std::sync::Arc as StdArc;

        let server = self.server.clone();
        let port = self.port;
        let uuid_bytes = self.uuid_bytes;
        let transport = StdArc::clone(&self.transport);
        let flow = self.flow;
        let dialer = Arc::clone(&self.dialer);
        #[cfg(feature = "vless-encryption")]
        let encryption = self.encryption.clone();

        let dial: DialFn = StdArc::new(move || {
            let server = server.clone();
            let transport = StdArc::clone(&transport);
            let dialer = Arc::clone(&dialer);
            #[cfg(feature = "vless-encryption")]
            let encryption = encryption.clone();
            Box::pin(async move {
                // Mux session dial — `internal: false`: a shared mux conn
                // exists to serve user streams regardless of which dial
                // triggered its establishment.
                let stream = dialer
                    .dial(&server, port, false)
                    .await
                    .map_err(MeowError::Io)?;
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
        dial
    }

    /// Vision UDP: one Mux.Cool session per association — the physical
    /// VLESS request is CommandMux (0x03) carrying the
    /// xtls-rprx-vision addon inside the first Vision record
    /// (`VlessConn::new_mux_deferred` + `VisionConn` in `mux_dial_fn`),
    /// and `MuxClient::open_packet_stream_for` opens the `network=UDP`
    /// substream on it.
    ///
    /// `self.mux` is deliberately not reused: the association gets a
    /// session of its own, mirroring the per-association
    /// `VlessPacketConn` the bare path hands out and keeping UDP off
    /// the TCP stream pool.  `Ok(None)` means the mux path declined —
    /// a `domain_udp_target` (Mux.Cool frames carry an `IpAddr`, not a
    /// name, per datagram); the caller warns once and falls back to the
    /// bare `Cmd::Udp` request.
    ///
    /// The caller does not drop the session early: `muxcool::PacketConn`
    /// pins the session for the association's life, and the transient
    /// `MuxClient` owns nothing else once this returns.
    #[cfg(all(feature = "mux", feature = "vless-vision"))]
    async fn dial_udp_vision(
        &self,
        metadata: &Metadata,
    ) -> Result<Option<Box<dyn ProxyPacketConn>>> {
        debug!(
            "VLESS vision UDP (Mux.Cool) connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );
        let mux = MuxClient::new(
            self.mux_dial_fn(Protocol::MuxCool),
            MuxOptions {
                protocol: Protocol::MuxCool,
                ..MuxOptions::default()
            },
        );
        mux.open_packet_stream_for(metadata, "vless").await
    }

    /// Attach a VLESS Encryption client (`encryption: mlkem768x25519plus…`).
    ///
    /// Shared across dials so the 0-RTT resumption ticket cache persists.
    #[cfg(feature = "vless-encryption")]
    pub fn set_encryption(&mut self, encryption: Option<Arc<ClientInstance>>) {
        self.encryption = encryption;
    }

    /// Dial a raw TCP + transport-chain stream to the VLESS server, then run the
    /// VLESS Encryption handshake if one is configured.  Returns the stream
    /// plus the per-phase timings [`dial_tcp`](ProxyAdapter::dial_tcp) reports
    /// as the `vless connect breakdown` debug line.
    async fn dial_stream(
        &self,
        internal: bool,
    ) -> Result<(Box<dyn meow_transport::Stream>, DialPhases)> {
        let mut phases = DialPhases::default();
        // A user dial straight to the server shares a multiplexed
        // (gRPC/xhttp) connection; probes and `dialer-proxy` chains keep
        // their own.
        let shared = !internal && !self.dialer.is_proxy();
        if shared {
            if let Some(stream) = self.transport.reuse().await {
                phases.reused = true;
                let t = Instant::now();
                let stream = self.encrypt(stream).await?;
                phases.transport_ms = t.elapsed().as_secs_f64() * 1000.0;
                return Ok((stream, phases));
            }
        }
        let t = Instant::now();
        let stream = self
            .dialer
            .dial(&self.server, self.port, internal)
            .await
            .map_err(MeowError::Io)?;
        phases.tcp_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        let stream = if shared {
            let stream = self.transport.connect_shared(stream).await?;
            self.encrypt(stream).await?
        } else {
            self.wrap_stream(stream).await?
        };
        phases.transport_ms = t.elapsed().as_secs_f64() * 1000.0;
        Ok((stream, phases))
    }

    /// The VLESS Encryption handshake, when one is configured.
    async fn encrypt(
        &self,
        stream: Box<dyn meow_transport::Stream>,
    ) -> Result<Box<dyn meow_transport::Stream>> {
        #[cfg(feature = "vless-encryption")]
        if let Some(encryption) = &self.encryption {
            return encryption.handshake(stream).await;
        }
        Ok(stream)
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
        self.encrypt(stream).await
    }

    /// Run the VLESS request exchange targeting `metadata` on `stream`
    /// (already transport-wrapped).  Shared by `dial_tcp` and `connect_over`.
    async fn handshake_tcp(
        &self,
        stream: Box<dyn meow_transport::Stream>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let addr = addr_from_metadata(metadata).map_err(MeowError::NotSupported)?;

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
        // With the `mux` + `vless-vision` pair compiled in, a vision
        // node's UDP rides a per-association Mux.Cool session — `self.udp`
        // covers it.  Without them there is no wire shape a strict server
        // accepts: a bare `Cmd::Udp` request carries no flow addon and
        // xray / sing-box ≥1.12 (vendored sing-vmess `vless.Service`
        // checks `request.Flow == account.Flow` on every command) reject
        // the mismatch, so the capability stays off rather than promising
        // a conn that blackholes.
        #[cfg(all(feature = "mux", feature = "vless-vision"))]
        let plain_udp = self.udp
            // A vision node whose configured mux pool is `only-tcp` has
            // no accepted wire shape: the pool declines UDP, the
            // transient session is skipped (a configured pool wins),
            // and strict servers reject the bare fallback — advertise
            // honestly instead of promising a conn that blackholes.
            && !(matches!(self.flow, Some(VlessFlow::XtlsRprxVision))
                && self
                    .mux
                    .as_ref()
                    .is_some_and(|m| !m.supports_udp()));
        #[cfg(not(all(feature = "mux", feature = "vless-vision")))]
        let plain_udp = self.udp && self.flow.is_none();
        // With mux enabled, UDP rides the mux TCP session (unless
        // `only-tcp` forces the plain path) — mirrors mihomo's
        // SingMux.SupportUDP.
        plain_udp || {
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

        let t0 = Instant::now();
        let (stream, phases) = self.dial_stream(metadata.is_internal()).await?;
        let t1 = Instant::now();
        let conn = self.handshake_tcp(stream, metadata).await?;
        // Establish breakdown: `tcp_ms` is the raw/front-hop dial
        // (`dialer-proxy` chains fold their front hop into it), `tls_ms`
        // the transport chain (BoringSSL handshake for `tls: true`),
        // `vless_ms` the VLESS request exchange — ~0 under Vision, whose
        // header is deferred into the first padded write (timed there as
        // `vision first payload write` / `vision first server data`).
        debug!(
            proxy = %self.name,
            dst = %metadata.remote_address(),
            tcp_ms = phases.tcp_ms,
            tls_ms = phases.transport_ms,
            vless_ms = t1.elapsed().as_secs_f64() * 1000.0,
            total_ms = t0.elapsed().as_secs_f64() * 1000.0,
            reused = phases.reused,
            "vless connect breakdown"
        );
        Ok(conn)
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
        let t0 = Instant::now();
        let stream = self.wrap_stream(Box::new(stream)).await?;
        let t1 = Instant::now();
        let conn = self.handshake_tcp(stream, metadata).await?;
        debug!(
            proxy = %self.name,
            dst = %metadata.remote_address(),
            tcp_ms = 0.0,
            tls_ms = (t1 - t0).as_secs_f64() * 1000.0,
            vless_ms = t1.elapsed().as_secs_f64() * 1000.0,
            total_ms = t0.elapsed().as_secs_f64() * 1000.0,
            relay = true,
            "vless connect breakdown"
        );
        Ok(conn)
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

        // A vision node with no configured mux pool still cannot emit a
        // bare `Cmd::Udp` request — strict servers reject its missing
        // flow addon.  Route the association through its own Mux.Cool
        // session instead (CommandMux request + xtls-rprx-vision addon +
        // `network=UDP` substream), the wire shape xray / mihomo /
        // sing-box clients use.
        #[cfg(all(feature = "mux", feature = "vless-vision"))]
        if self.mux.is_none() && matches!(self.flow, Some(VlessFlow::XtlsRprxVision)) {
            if let Some(conn) = self.dial_udp_vision(metadata).await? {
                return Ok(conn);
            }
        }

        // Reaching the bare `Cmd::Udp` request for a flow user means the
        // Mux.Cool route declined — a domain UDP target it cannot express
        // (or `only-tcp` on the configured pool).  Strict servers reject
        // the flow mismatch; warn once, then attempt the request anyway
        // for tolerant listeners rather than silently blackholing.
        #[cfg(all(feature = "mux", feature = "vless-vision"))]
        if matches!(self.flow, Some(VlessFlow::XtlsRprxVision))
            && !self.vision_udp_bare_warned.swap(true, Ordering::Relaxed)
        {
            let reason = if self.mux.as_ref().is_some_and(|m| !m.supports_udp()) {
                "the configured mux pool is only-tcp"
            } else {
                "Mux.Cool cannot express a domain UDP target"
            };
            tracing::warn!(
                proxy = %self.name,
                "vless: UDP for flow xtls-rprx-vision fell back to a bare Cmd::Udp request \
                 ({reason}): strict servers \
                 (xray, sing-box >=1.12) reject it as a flow mismatch"
            );
        }

        // Without the `mux` + `vless-vision` pair compiled in there is no
        // wire shape a strict server accepts for vision UDP — refuse as a
        // capability error (matching `support_udp`) rather than return a
        // conn that blackholes.
        #[cfg(not(all(feature = "mux", feature = "vless-vision")))]
        if matches!(self.flow, Some(VlessFlow::XtlsRprxVision)) {
            return Err(MeowError::NotSupported(format!(
                "vless '{}': xtls-rprx-vision UDP needs a Mux.Cool session — \
                 rebuild with the `mux` and `vless-vision` features (a bare \
                 Cmd::Udp request carries no flow addon and strict servers \
                 reject it)",
                self.name
            )));
        }

        // Non-vision UDP is the plain VLESS `Cmd::Udp` request — no flow
        // addon, matching every upstream client.
        debug!(
            "VLESS UDP connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );

        // A >255-byte host cannot ride the one-byte domain length — refuse
        // as `NotSupported` so a chained `dial_udp_conn` caller falls back to
        // a locally-resolved `UdpTarget::Addr` instead of a truncated wire
        // frame (issue #657).  Checked before dialing so the refusal costs
        // no handshake.
        let addr = addr_from_metadata(metadata).map_err(MeowError::NotSupported)?;
        let (stream, _phases) = self.dial_stream(metadata.is_internal()).await?;

        let conn = VlessPacketConn::new(stream, &self.uuid_bytes, metadata.dst_port, &addr).await?;

        Ok(Box::new(conn))
    }

    /// Issue #695: close every pooled mux session and forget the shared
    /// gRPC/xhttp connection, so the next dial opens a fresh physical one
    /// (see `MuxClient::reset`, `TransportChain::reset`).
    fn reset_sessions(&self) {
        #[cfg(feature = "mux")]
        if let Some(mux) = &self.mux {
            mux.reset();
        }
        self.transport.reset();
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }

    fn client_fingerprint(&self) -> Option<&str> {
        self.transport.tls_fingerprint()
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

    // ─── E6: vision UDP capability tracks the Mux.Cool route ─────────────────

    // Runtime behavior is covered by the `vision_udp_mux` integration
    // tests.  With the `mux` + `vless-vision` pair compiled in, a
    // per-association Mux.Cool session carries vision UDP, so `udp: true`
    // advertises the capability.
    #[cfg(all(feature = "mux", feature = "vless-vision"))]
    #[test]
    fn vless_vision_udp_supported_via_muxcool() {
        assert!(make_adapter(Some(VlessFlow::XtlsRprxVision), true).support_udp());
        assert!(!make_adapter(Some(VlessFlow::XtlsRprxVision), false).support_udp());
        assert!(make_adapter(None, true).support_udp());
    }

    // A vision node whose configured mux pool is `only-tcp` has no
    // accepted wire shape — the pool declines UDP, the transient
    // session is skipped (a configured pool wins), and strict servers
    // reject the bare fallback — so it advertises no UDP capability.
    // A non-vision node on the same pool still carries `Cmd::Udp`.
    #[cfg(all(feature = "mux", feature = "vless-vision"))]
    #[test]
    fn vless_vision_udp_unsupported_with_only_tcp_pool() {
        let vision = make_adapter(Some(VlessFlow::XtlsRprxVision), true).with_mux(MuxOptions {
            protocol: Protocol::MuxCool,
            only_tcp: true,
            ..MuxOptions::default()
        });
        assert!(!vision.support_udp());
        let plain = make_adapter(None, true).with_mux(MuxOptions {
            protocol: Protocol::MuxCool,
            only_tcp: true,
            ..MuxOptions::default()
        });
        assert!(plain.support_udp());
    }

    // Without the mux pair there is no wire shape a strict server accepts
    // for a flow user's UDP — `support_udp` stays off so a group does not
    // pick the member for UDP; non-vision UDP is unchanged.
    #[cfg(not(all(feature = "mux", feature = "vless-vision")))]
    #[test]
    fn vless_vision_udp_unsupported_without_muxcool() {
        assert!(!make_adapter(Some(VlessFlow::XtlsRprxVision), true).support_udp());
        assert!(make_adapter(None, true).support_udp());
    }
}
