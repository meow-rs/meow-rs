//! The QUIC/TLS configuration for the HTTP/3 transport.
//!
//! quiche links the same vendored BoringSSL as `meow-transport` (via the
//! `boring` crate), so the trust decision is expressed with
//! `boring::ssl::SslContextBuilder` and handed to quiche — no second crypto
//! library, and the same Mozilla root bundle the `TlsLayer` uses.

use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use std::{io, net::IpAddr, time::Duration};

/// The only protocol this transport may negotiate (PROTOCOL.md §3.2).
pub(super) const ALPN_H3: &[u8] = b"h3";
/// Per-stream and whole-connection receive windows. A proxied flow is a
/// stream, so the stream window is what bounds a single download's in-flight
/// bytes; the connection window is deliberately larger but not a multiple of
/// the per-connection stream count, which is what keeps one busy flow from
/// starving its siblings.
const STREAM_RECEIVE_WINDOW: u64 = 4 * 1024 * 1024;
const CONN_RECEIVE_WINDOW: u64 = 16 * 1024 * 1024;
/// Streams the *endpoint* may open towards us. TrustTunnel never has the
/// server initiate a request, so this only needs to be non-zero; the uni
/// allowance has to cover HTTP/3's own control and QPACK streams.
const PEER_STREAMS: u64 = 16;

/// Build the client QUIC config for one TrustTunnel endpoint.
///
/// `ip` is set when the endpoint is named by an IP literal: the connector
/// then gives quiche no server name, and the certificate is checked against
/// that address's `iPAddress` SAN here instead. `extra_roots` are DER
/// certificates trusted beside the webpki bundle, as `TlsConfig`'s
/// `additional_roots` are on the HTTP/2 path. `idle` is the QUIC idle
/// timeout; see [`super::QuicConnector`] for how the spec's
/// `2 × (connection_timeout + health_check_timeout)` is derived.
pub(super) fn build(
    insecure: bool,
    ip: Option<IpAddr>,
    extra_roots: &[Vec<u8>],
    idle: Duration,
) -> io::Result<quiche::Config> {
    let mut ssl = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| io::Error::other(format!("TrustTunnel BoringSSL context: {e}")))?;
    if insecure {
        ssl.set_verify(SslVerifyMode::NONE);
    } else {
        // BoringSSL's default store is empty, so the roots must be seeded
        // explicitly or every chain fails.
        let mut store = boring::x509::store::X509StoreBuilder::new()
            .map_err(|e| io::Error::other(format!("TrustTunnel X509StoreBuilder: {e}")))?;
        let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(AsRef::as_ref)
            .chain(extra_roots.iter().map(Vec::as_slice));
        for cert in roots {
            let parsed = boring::x509::X509::from_der(cert)
                .map_err(|e| io::Error::other(format!("TrustTunnel root cert: {e}")))?;
            store
                .add_cert(parsed)
                .map_err(|e| io::Error::other(format!("TrustTunnel root store: {e}")))?;
        }
        // For a DNS name, quiche installs the server name as the verify-param
        // hostname per connection, so `PEER` covers the chain *and* the name.
        // An IP literal is never handed to quiche (it would be compared as a
        // DNS name and never match an `iPAddress` SAN), so it is pinned on
        // this connector's own store instead: every chain verification
        // inherits the store's param, and the per-connection param, which
        // carries no address, cannot clear it.
        if let Some(ip) = ip {
            store
                .verify_param_mut()
                .set_ip(ip)
                .map_err(|e| io::Error::other(format!("TrustTunnel verify address: {e}")))?;
        }
        ssl.set_cert_store_builder(store);
        ssl.set_verify(SslVerifyMode::PEER);
    }

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)
        .map_err(|e| io::Error::other(format!("TrustTunnel quiche config: {e}")))?;
    config
        .set_application_protos(&[ALPN_H3])
        .map_err(|e| io::Error::other(format!("TrustTunnel quiche ALPN: {e}")))?;
    config.set_max_idle_timeout(u64::try_from(idle.as_millis()).unwrap_or(u64::MAX));
    config.set_initial_max_data(CONN_RECEIVE_WINDOW);
    config.set_initial_max_stream_data_bidi_local(STREAM_RECEIVE_WINDOW);
    config.set_initial_max_stream_data_bidi_remote(STREAM_RECEIVE_WINDOW);
    config.set_initial_max_stream_data_uni(STREAM_RECEIVE_WINDOW);
    config.set_initial_max_streams_bidi(PEER_STREAMS);
    config.set_initial_max_streams_uni(PEER_STREAMS);
    // QUIC-bit greasing and the datagram extension are both left at quiche's
    // default (on, off): a tunnel whose whole point is to look like ordinary
    // HTTP/3 should not advertise a transport parameter no browser sends,
    // and the protocol carries UDP on streams, so DATAGRAM frames would be
    // a capability nothing in this client ever uses.
    Ok(config)
}
