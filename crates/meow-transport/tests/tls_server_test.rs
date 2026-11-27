//! Server-side BoringTLS acceptor tests: TLS 1.3 handshake and the same
//! independent raw-passthrough switches Vision uses on outbound streams.

mod support;

use meow_transport::tls::server::{TlsServer, TlsServerConfig};
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::{
    enable_raw_read_passthrough, enable_raw_write_passthrough, supports_raw_passthrough, Transport,
};
use support::loopback::gen_cert;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn server_config(alpn: &[&str]) -> (TlsServerConfig, Vec<u8>) {
    let (cert_der, _key_der, cert_pem, key_pem) = gen_cert(&["localhost"]);
    (
        TlsServerConfig {
            certificate_chain_pem: cert_pem.into_bytes(),
            private_key_pem: key_pem.into_bytes(),
            alpn: alpn.iter().map(|s| (*s).to_string()).collect(),
        },
        cert_der.as_ref().to_vec(),
    )
}

#[tokio::test]
async fn accept_tls13_round_trip_and_independent_raw_switches() {
    let (server_config, root) = server_config(&["h2"]);
    let server = TlsServer::new(&server_config).expect("server config");
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });

    let mut client_config = TlsConfig::new("localhost");
    client_config.additional_roots.push(root);
    client_config.alpn = vec!["h2".into()];
    let layer = TlsLayer::new(&client_config).expect("client TLS layer");
    let mut client = layer
        .connect(Box::new(client_io))
        .await
        .expect("client handshake");

    let mut server = accept_task
        .await
        .expect("accept task")
        .expect("server handshake");
    assert!(supports_raw_passthrough(client.as_mut()));
    assert!(supports_raw_passthrough(server.as_mut()));

    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    assert!(enable_raw_write_passthrough(server.as_mut()));
    assert!(enable_raw_read_passthrough(client.as_mut()));
    server.write_all(b"raw-s2c").await.unwrap();
    server.flush().await.unwrap();
    let mut raw = vec![0u8; b"raw-s2c".len()];
    client.read_exact(&mut raw).await.unwrap();
    assert_eq!(raw, b"raw-s2c");

    assert!(enable_raw_write_passthrough(client.as_mut()));
    assert!(enable_raw_read_passthrough(server.as_mut()));
    client.write_all(b"raw-c2s").await.unwrap();
    client.flush().await.unwrap();
    let mut raw = vec![0u8; b"raw-c2s".len()];
    server.read_exact(&mut raw).await.unwrap();
    assert_eq!(raw, b"raw-c2s");
}

#[tokio::test]
async fn offered_alpn_without_overlap_fails_handshake() {
    let (server_config, root) = server_config(&["h2"]);
    let server = TlsServer::new(&server_config).expect("server config");
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });

    let mut client_config = TlsConfig::new("localhost");
    client_config.additional_roots.push(root);
    client_config.alpn = vec!["http/1.1".into()];
    let layer = TlsLayer::new(&client_config).expect("client TLS layer");
    let client_result = layer.connect(Box::new(client_io)).await;
    assert!(client_result.is_err(), "ALPN mismatch must fail");
    assert!(accept_task.await.expect("accept task").is_err());
}

// Evidence for the REALITY native-flight decision: a stock BoringSSL server
// must not emit a server flight when its only credential is Ed25519 but the
// Chrome-shaped peer omits Ed25519 from signature_algorithms.  If this ever
// fails, BoringSSL's credential selection stopped enforcing the peer
// intersection and the decision record needs re-evaluation.
#[tokio::test]
async fn stock_server_ed25519_chrome_sigalgs_emit_no_server_flight() {
    use boring::ssl::{SslConnector, SslMethod};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    struct CaptureRead {
        inner: DuplexStream,
        seen: Arc<Mutex<Vec<u8>>>,
    }
    impl AsyncRead for CaptureRead {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            let out = Pin::new(&mut this.inner).poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = &out {
                let filled = buf.filled();
                this.seen
                    .lock()
                    .unwrap()
                    .extend_from_slice(&filled[before..]);
            }
            out
        }
    }
    impl AsyncWrite for CaptureRead {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&key_pair)
        .expect("ed25519 cert");
    // ring emits a PKCS#8 v2 Ed25519 key (version 1 with the public key
    // appended); BoringSSL's parser accepts the canonical v1 form.  Both
    // forms carry the same 32-byte seed at the same offset.
    let ring_der = key_pair.serialize_der();
    assert_eq!(
        &ring_der[..16],
        &[
            0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20
        ]
    );
    let mut pkcs8_v1 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8_v1.extend_from_slice(&ring_der[16..48]);
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_v1);
    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----
{b64}
-----END PRIVATE KEY-----
"
    );
    let server = TlsServer::new(&TlsServerConfig {
        certificate_chain_pem: cert.pem().into_bytes(),
        private_key_pem: key_pem.into_bytes(),
        alpn: vec![],
    })
    .expect("ed25519 server config");

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = CaptureRead {
        inner: client_io,
        seen: Arc::clone(&seen),
    };
    let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });

    let mut connector = SslConnector::builder(SslMethod::tls()).expect("connector");
    connector
        .set_sigalgs_list(
            "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
             ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
             rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
        )
        .expect("Chrome 133 sigalgs");
    let ssl = connector
        .build()
        .configure()
        .expect("configure")
        .into_ssl("localhost")
        .expect("ssl");
    let client_result = tokio_boring::SslStreamBuilder::new(ssl, capture)
        .connect()
        .await;
    assert!(client_result.is_err(), "Chrome sigalgs omit Ed25519");
    assert!(accept_task.await.expect("accept task").is_err());
    let seen = seen.lock().unwrap();
    assert!(
        seen.first().copied() != Some(0x16),
        "stock BoringSSL emitted a server flight despite no Ed25519 intersection: {:02x?}",
        &seen[..seen.len().min(32)]
    );
}
