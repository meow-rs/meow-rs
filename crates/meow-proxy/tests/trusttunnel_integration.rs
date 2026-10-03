#![cfg(feature = "trusttunnel")]
//! Loopback TLS/H2 endpoint: certificate policy, auth mapping, and dial context.

use async_trait::async_trait;
use bytes::Bytes;
use meow_common::{MeowError, Metadata, ProxyAdapter};
use meow_proxy::{
    dialer::{DirectDialer, TcpDialer},
    trusttunnel::{Options, TrustTunnelAdapter},
};
use meow_transport::{tls::TlsConfig, Stream};
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpListener};

struct Endpoint {
    addr: SocketAddr,
    cert: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Endpoint {
    async fn start(h2_alpn: bool) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = generated.cert.der().to_vec();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()),
        );
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone().into()], key)
            .unwrap();
        if h2_alpn {
            tls.alpn_protocols = vec![b"h2".to_vec()];
        }
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Ok(mut connection) = h2::server::handshake(tls).await else {
                        return;
                    };
                    while let Some(Ok((request, mut response))) = connection.accept().await {
                        assert_eq!(request.method(), http::Method::CONNECT);
                        let authorized = request.headers().get("proxy-authorization")
                            == Some(&http::HeaderValue::from_static(
                                "Basic Zml4dHVyZTpzZWNyZXQ=",
                            ));
                        let check = request.uri().authority().unwrap().as_str() == "_check";
                        let reply = http::Response::builder()
                            .status(if authorized { 200 } else { 407 })
                            .body(())
                            .unwrap();
                        let Ok(mut send) = response.send_response(reply, check || !authorized)
                        else {
                            continue;
                        };
                        if check || !authorized {
                            continue;
                        }
                        let mut recv = request.into_body();
                        tokio::spawn(async move {
                            while let Some(Ok(mut data)) = recv.data().await {
                                recv.flow_control().release_capacity(data.len()).unwrap();
                                while !data.is_empty() {
                                    send.reserve_capacity(data.len());
                                    let Some(Ok(capacity)) =
                                        std::future::poll_fn(|cx| send.poll_capacity(cx)).await
                                    else {
                                        return;
                                    };
                                    if capacity > 0
                                        && send
                                            .send_data(
                                                data.split_to(capacity.min(data.len())),
                                                false,
                                            )
                                            .is_err()
                                    {
                                        return;
                                    }
                                }
                            }
                            let _ = send.send_data(Bytes::new(), true);
                        });
                    }
                });
            }
        });
        Self { addr, cert, task }
    }

    fn tls(&self, trust: bool, name: &str) -> TlsConfig {
        let mut tls = TlsConfig::new(name);
        if trust {
            tls.additional_roots.push(self.cert.clone());
        }
        tls
    }

    fn adapter(
        &self,
        tls: TlsConfig,
        password: &str,
        dialer: Arc<dyn TcpDialer>,
    ) -> TrustTunnelAdapter {
        TrustTunnelAdapter::new(
            "fixture",
            "127.0.0.1",
            self.addr.port(),
            tls,
            Options::new("fixture".into(), password.into()),
            true,
            dialer,
        )
        .unwrap()
    }
}

fn destination() -> Metadata {
    Metadata {
        host: "echo.example.test".into(),
        dst_port: 443,
        ..Default::default()
    }
}

#[tokio::test]
async fn trusted_tls_connect_echo_and_half_close() {
    let endpoint = Endpoint::start(true).await;
    let proxy = endpoint.adapter(
        endpoint.tls(true, "localhost"),
        "secret",
        Arc::new(DirectDialer),
    );
    let mut stream = proxy.dial_tcp(&destination()).await.unwrap();
    stream.write_all(b"payload").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"payload");
}

#[tokio::test]
async fn untrusted_root_and_wrong_certificate_name_fail() {
    let endpoint = Endpoint::start(true).await;
    for tls in [
        endpoint.tls(false, "localhost"),
        endpoint.tls(true, "wrong.example.test"),
    ] {
        let proxy = endpoint.adapter(tls, "secret", Arc::new(DirectDialer));
        let error = proxy.dial_tcp(&destination()).await.err().unwrap();
        assert!(error.to_string().contains("certificate"));
    }
}

#[tokio::test]
async fn endpoint_without_h2_alpn_is_rejected() {
    let endpoint = Endpoint::start(false).await;
    let proxy = endpoint.adapter(
        endpoint.tls(true, "localhost"),
        "secret",
        Arc::new(DirectDialer),
    );
    let error = proxy.dial_tcp(&destination()).await.err().unwrap();
    assert!(error.to_string().contains("negotiate h2"));
}

#[tokio::test]
async fn authentication_failure_maps_to_proxy_auth_error() {
    let endpoint = Endpoint::start(true).await;
    let proxy = endpoint.adapter(
        endpoint.tls(true, "localhost"),
        "incorrect",
        Arc::new(DirectDialer),
    );
    assert!(matches!(
        proxy.dial_tcp(&destination()).await,
        Err(MeowError::ProxyAuthFailed)
    ));
}

struct ContextDialer(Arc<AtomicUsize>);
#[async_trait]
impl TcpDialer for ContextDialer {
    async fn dial(&self, host: &str, port: u16, internal: bool) -> io::Result<Box<dyn Stream>> {
        self.0.store(if internal { 2 } else { 1 }, Ordering::SeqCst);
        DirectDialer.dial(host, port, internal).await
    }
}

#[tokio::test]
async fn internal_dials_preserve_the_usage_accounting_hint() {
    let endpoint = Endpoint::start(true).await;
    let observed = Arc::new(AtomicUsize::new(0));
    let proxy = endpoint.adapter(
        endpoint.tls(true, "localhost"),
        "secret",
        Arc::new(ContextDialer(Arc::clone(&observed))),
    );
    let mut metadata = destination();
    metadata.internal = true;
    let stream = proxy.dial_tcp(&metadata).await.unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 2);
    drop(stream);
    proxy.reset_sessions();
    metadata.internal = false;
    let _next = proxy.dial_tcp(&metadata).await.unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}
