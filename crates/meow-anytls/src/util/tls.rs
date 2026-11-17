//! TLS plumbing.
//!
//! **Client side** is TLS-library-agnostic: the host hands the
//! [`Client`](crate::client::Client) an implementation of [`TlsConnect`] that turns a
//! freshly dialled `TcpStream` into a handshaken TLS stream. In meow that is
//! `meow-transport`'s BoringSSL `TlsLayer`; this crate links no TLS library
//! for the client at all.
//!
//! **Server side** (feature `server`) keeps the rustls-based acceptor
//! helpers the upstream fork ships.

use crate::util::{AnyTlsError, Result};
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// A handshaken client-side TLS stream, as returned by [`TlsConnect::connect`].
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncStream for T {}

/// An [`AsyncStream`] that is also `Sync` — the currency a
/// [`TransportDialer`](crate::util::TransportDialer) returns.
///
/// `Sync` is part of the dialer's contract rather than the client's: a
/// host TLS hook keeps the transport reachable through `&` references
/// (BoringSSL's `SslStream<S>`, conn tables), so a stream that only
/// satisfies `Send` cannot be handed to
/// [`TlsConnect::connect_stream`].
pub trait SyncStream: AsyncStream + Sync {}
impl<T: AsyncStream + Sync + ?Sized> SyncStream for T {}

/// Future returned by [`TlsConnect::connect`] and
/// [`TlsConnect::connect_stream`].
pub type TlsConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn AsyncStream>>> + Send + 'a>>;

/// Host-supplied TLS client hook.
///
/// The implementation owns SNI, ALPN, certificate verification and any
/// fingerprint shaping; the client only needs the resulting stream.
pub trait TlsConnect: Send + Sync {
    /// Perform the TLS handshake over `tcp`.
    fn connect(&self, tcp: TcpStream) -> TlsConnectFuture<'_>;

    /// Perform the TLS handshake over an already-connected transport —
    /// what the client asks for when a
    /// [`TransportDialer`](crate::util::TransportDialer) supplied the
    /// underlying stream (a connection tunnelled through another proxy,
    /// not a `TcpStream` it can name). The default refuses: a hook that
    /// only knows `TcpStream` cannot lift a chained connection, and
    /// failing the dial loudly beats carrying AnyTLS plaintext.
    fn connect_stream(&self, stream: Box<dyn SyncStream>) -> TlsConnectFuture<'_> {
        let _ = stream;
        Box::pin(async {
            Err(AnyTlsError::Tls(
                "the TLS hook cannot handshake over a chained transport".to_string(),
            ))
        })
    }
}

// ─── Server side (rustls) ────────────────────────────────────────────────────

#[cfg(feature = "server")]
mod server_tls {
    use crate::util::{AnyTlsError, Result};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::ServerConfig;
    use std::sync::Arc;
    use std::{fs::File, io::BufReader, path::Path};

    impl From<rustls::Error> for AnyTlsError {
        fn from(err: rustls::Error) -> Self {
            AnyTlsError::Tls(format!("rustls error: {}", err))
        }
    }

    impl From<rcgen::Error> for AnyTlsError {
        fn from(err: rcgen::Error) -> Self {
            AnyTlsError::Tls(format!("rcgen error: {}", err))
        }
    }

    /// Generate a self-signed certificate for testing
    ///
    /// This generates a certificate similar to the Go version:
    /// - ECDSA P-256 key (default for rcgen, better performance than RSA 2048)
    /// - Valid for reasonable duration (rcgen default, typically 1 year)
    /// - Server authentication usage
    /// - Supports localhost and custom server names
    pub fn generate_key_pair() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        generate_key_pair_with_name(None)
    }

    /// Generate a self-signed certificate with a specific server name
    pub fn generate_key_pair_with_name(
        server_name: Option<&str>,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        // Determine server name to use
        let name = server_name.unwrap_or("localhost");

        // Use rcgen's simple API to generate self-signed certificate
        // This is the recommended approach for basic use cases
        let subject_alt_names = vec![name.to_string(), "localhost".to_string()];
        let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)?;

        // Serialize to DER format
        let cert_der = certified_key.cert.der();
        let key_der = certified_key.signing_key.serialize_der();

        // Convert to rustls types
        // CertificateDer implements From<&[u8]>, but we need 'static lifetime
        // So we clone into a Vec<u8> and use it
        let cert_der_vec: Vec<u8> = cert_der.to_vec();
        let cert_der: CertificateDer<'static> = cert_der_vec.into();
        let key_der: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(key_der.into());

        Ok((cert_der, key_der))
    }

    /// Create a server TLS config with a generated certificate
    pub fn create_server_config() -> Result<Arc<ServerConfig>> {
        let (cert, key) = generate_key_pair()?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        Ok(Arc::new(config))
    }

    /// Create a server TLS config by loading certificate/private key from disk (PEM).
    pub fn create_server_config_from_files<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
    ) -> Result<Arc<ServerConfig>> {
        let cert_file = File::open(&cert_path).map_err(AnyTlsError::Io)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| AnyTlsError::Tls(format!("failed to parse certificate: {e}")))?;
        if certs.is_empty() {
            return Err(AnyTlsError::Tls(format!(
                "no certificates found in {:?}",
                cert_path.as_ref()
            )));
        }

        let key_file = File::open(&key_path).map_err(AnyTlsError::Io)?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| AnyTlsError::Tls(format!("failed to parse private key: {e}")))?
            .ok_or_else(|| {
                AnyTlsError::Tls(format!("no private key found in {:?}", key_path.as_ref()))
            })?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(Arc::new(config))
    }
}

#[cfg(feature = "server")]
pub use server_tls::*;

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::server_tls::*;
    use rustls::pki_types::PrivateKeyDer;
    use std::sync::Arc;

    // `ServerConfig::builder()` below auto-detects the process CryptoProvider
    // and panics if two are ever linked. Install ring explicitly first,
    // matching meow's integration tests. Idempotent — ignores the Err when a
    // default is already set.
    fn install_ring() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn test_generate_key_pair() {
        // Should now succeed
        let (cert, key) = generate_key_pair().unwrap();
        assert!(!cert.as_ref().is_empty());
        match &key {
            PrivateKeyDer::Pkcs8(data) => assert!(!data.secret_pkcs8_der().is_empty()),
            PrivateKeyDer::Pkcs1(data) => assert!(!data.secret_pkcs1_der().is_empty()),
            PrivateKeyDer::Sec1(data) => assert!(!data.secret_sec1_der().is_empty()),
            _ => panic!("Unexpected key type"),
        }
    }

    #[test]
    fn test_generate_key_pair_with_name() {
        let (cert, key) = generate_key_pair_with_name(Some("example.com")).unwrap();
        assert!(!cert.as_ref().is_empty());
        match &key {
            PrivateKeyDer::Pkcs8(data) => assert!(!data.secret_pkcs8_der().is_empty()),
            PrivateKeyDer::Pkcs1(data) => assert!(!data.secret_pkcs1_der().is_empty()),
            PrivateKeyDer::Sec1(data) => assert!(!data.secret_sec1_der().is_empty()),
            _ => panic!("Unexpected key type"),
        }
    }

    #[test]
    fn test_create_server_config() {
        install_ring();
        // Should now succeed
        let config = create_server_config().unwrap();
        assert!(Arc::strong_count(&config) >= 1);
    }
}
