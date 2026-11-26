//! TLS server acceptor for inbound transports that need Vision's raw
//! passthrough switch.
//!
//! This is deliberately an acceptor over an already-established stream, not
//! a socket listener: binding, firewall policy, connection caps and deadlines
//! belong to the inbound listener crate.  The returned stream uses the same
//! BoringSSL raw-switch implementation as client connections from
//! [`TlsLayer`](crate::tls::TlsLayer), so the independent read/write raw
//! switches have one implementation and one contract.

use std::io;

use boring::ssl::{AlpnError, SslAcceptor, SslMethod, SslOptions, SslSessionCacheMode, SslVersion};

use super::boring_stream::BoringTlsStream;
use crate::{Result, Stream, TransportError};

/// Certificate/key and ALPN policy for [`TlsServer`].
///
/// `certificate_chain_pem` is ordered leaf first.  Both PEM blobs are parsed
/// once at startup; nothing here performs file or network I/O.
#[derive(Clone)]
pub struct TlsServerConfig {
    pub certificate_chain_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    /// Server preference order.  Empty means no ALPN extension.  A client
    /// that offers ALPN but shares no protocol fails the handshake; a client
    /// that offers none still connects without ALPN.
    pub alpn: Vec<String>,
}

impl std::fmt::Debug for TlsServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerConfig")
            .field("certificate_chain_pem", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .field("alpn", &self.alpn)
            .finish()
    }
}

/// BoringSSL TLS 1.3 server acceptor producing raw-switchable streams.
#[derive(Clone)]
pub struct TlsServer {
    acceptor: SslAcceptor,
}

impl TlsServer {
    /// Build the acceptor and validate the certificate/key pair at startup.
    pub fn new(config: &TlsServerConfig) -> Result<Self> {
        let certs =
            boring::x509::X509::stack_from_pem(&config.certificate_chain_pem).map_err(|e| {
                TransportError::Config(format!("TLS server certificate: invalid PEM: {e}"))
            })?;
        if certs.is_empty() {
            return Err(TransportError::Config(
                "TLS server certificate: PEM carries no certificate".into(),
            ));
        }
        let key =
            boring::pkey::PKey::private_key_from_pem(&config.private_key_pem).map_err(|e| {
                TransportError::Config(format!("TLS server private-key: invalid PEM: {e}"))
            })?;

        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map_err(|e| TransportError::Config(format!("TLS server acceptor init: {e}")))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| TransportError::Config(format!("TLS server min-version: {e}")))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| TransportError::Config(format!("TLS server max-version: {e}")))?;
        builder.set_options(SslOptions::NO_TICKET);
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);

        let leaf = certs.first().expect("non-empty checked above");
        builder
            .set_certificate(leaf)
            .map_err(|e| TransportError::Config(format!("TLS server certificate: {e}")))?;
        for extra in &certs[1..] {
            builder.add_extra_chain_cert(extra.clone()).map_err(|e| {
                TransportError::Config(format!("TLS server certificate chain: {e}"))
            })?;
        }
        builder
            .set_private_key(&key)
            .map_err(|e| TransportError::Config(format!("TLS server private-key: {e}")))?;
        builder.check_private_key().map_err(|e| {
            TransportError::Config(format!(
                "TLS server certificate and private-key do not form a pair: {e}"
            ))
        })?;

        if !config.alpn.is_empty() {
            if config.alpn.len() > 16 {
                return Err(TransportError::Config(
                    "TLS server ALPN accepts at most 16 protocols".into(),
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for proto in &config.alpn {
                if proto.is_empty()
                    || proto.len() > 255
                    || !proto.bytes().all(|b| (0x20..=0x7e).contains(&b))
                {
                    return Err(TransportError::Config(format!(
                        "TLS server ALPN protocol must be 1..255 printable ASCII bytes: {proto:?}"
                    )));
                }
                if !seen.insert(proto) {
                    return Err(TransportError::Config(format!(
                        "TLS server ALPN protocol duplicated: {proto:?}"
                    )));
                }
            }
            let server_alpn = config.alpn.clone();
            builder.set_alpn_select_callback(move |_, client| {
                for wanted in &server_alpn {
                    let mut pos = 0;
                    while pos < client.len() {
                        let len = client[pos] as usize;
                        let start = pos + 1;
                        let Some(end) = start.checked_add(len).filter(|end| *end <= client.len())
                        else {
                            return Err(AlpnError::ALERT_FATAL);
                        };
                        if len != 0 && &client[start..end] == wanted.as_bytes() {
                            return Ok(&client[start..end]);
                        }
                        pos = end;
                    }
                }
                Err(AlpnError::ALERT_FATAL)
            });
        }

        Ok(Self {
            acceptor: builder.build(),
        })
    }

    /// Run the TLS server handshake over one already-connected stream.
    pub async fn accept(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let tls = tokio_boring::accept(&self.acceptor, inner)
            .await
            .map_err(|e| handshake_error(&e))?;
        Ok(Box::new(BoringTlsStream::new(tls)))
    }
}

fn handshake_error<S>(e: &tokio_boring::HandshakeError<S>) -> TransportError {
    match e.as_io_error() {
        Some(io_err) => TransportError::Io(match io_err.raw_os_error() {
            Some(errno) => io::Error::from_raw_os_error(errno),
            None => io::Error::new(io_err.kind(), format!("boring TLS accept: {e}")),
        }),
        None => TransportError::Tls(format!("boring TLS accept: {e}")),
    }
}
