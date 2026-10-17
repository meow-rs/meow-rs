#![cfg(feature = "trusttunnel")]
//! Loopback TLS/H2 endpoint: certificate policy, auth mapping, and dial context.

use async_trait::async_trait;
use bytes::Bytes;
use meow_common::{MeowError, Metadata, Proxy, ProxyAdapter};
use meow_proxy::{
    dialer::{DirectDialer, ProxyDialer, TcpDialer},
    group::load_balance::{LbStrategy, LoadBalanceGroup},
    trusttunnel::{CertificateVerificationError, Options, Transport, TrustTunnelAdapter},
    DirectAdapter,
};
use meow_transport::{tls::TlsConfig, Stream};
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpListener};

struct Endpoint {
    addr: SocketAddr,
    cert: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
    app_names: Arc<Mutex<Vec<Vec<u8>>>>,
    checks: Arc<AtomicUsize>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Endpoint {
    async fn start(h2_alpn: bool) -> Self {
        Self::start_for(h2_alpn, "localhost").await
    }

    /// `name` is the certificate's only SAN: a DNS name, or an IP literal,
    /// which rcgen encodes as an `iPAddress` SAN.
    async fn start_for(h2_alpn: bool, name: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let generated = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
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
        let app_names = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&app_names);
        let checks = Arc::new(AtomicUsize::new(0));
        let observed_checks = Arc::clone(&checks);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let observed = Arc::clone(&observed);
                let observed_checks = Arc::clone(&observed_checks);
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
                        let authority = request.uri().authority().unwrap().as_str();
                        let check = authority == "_check";
                        let udp = authority == "_udp2";
                        if check {
                            observed_checks.fetch_add(1, Ordering::SeqCst);
                        }
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
                        let observed = Arc::clone(&observed);
                        tokio::spawn(async move {
                            let mut pending = Vec::new();
                            while let Some(Ok(mut data)) = recv.data().await {
                                recv.flow_control().release_capacity(data.len()).unwrap();
                                if udp {
                                    pending.extend_from_slice(&data);
                                    while pending.len() >= 4 {
                                        let size =
                                            u32::from_be_bytes(pending[..4].try_into().unwrap())
                                                as usize;
                                        if pending.len() < size + 4 {
                                            break;
                                        }
                                        let app_len = pending[40] as usize;
                                        observed
                                            .lock()
                                            .unwrap()
                                            .push(pending[41..41 + app_len].to_vec());
                                        pending.drain(..4 + size);
                                    }
                                    continue;
                                }
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
        Self {
            addr,
            cert,
            task,
            app_names,
            checks,
        }
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
            Transport::H2,
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
    for (tls, expected) in [
        (endpoint.tls(false, "localhost"), 18),
        (endpoint.tls(true, "wrong.example.test"), 62),
    ] {
        let proxy = endpoint.adapter(tls, "secret", Arc::new(DirectDialer));
        let error = proxy.dial_tcp(&destination()).await.err().unwrap();
        let MeowError::Io(error) = error else {
            panic!("expected typed TLS IO failure")
        };
        let certificate = error
            .get_ref()
            .unwrap()
            .downcast_ref::<CertificateVerificationError>()
            .expect("must classify the actual certificate verification failure");
        assert_eq!(certificate.code(), expected);
    }
}

/// `server: 127.0.0.1` with no `sni:` — the parser defaults the TLS name to
/// the literal, which `TlsLayer` keeps out of SNI (RFC 6066 §3) and verifies
/// against the leaf's `iPAddress` SAN. The HTTP/3 transport must accept the
/// same certificate; its half of the pair is the same-named test in
/// `src/trusttunnel/protocol/http3/tests.rs`.
#[tokio::test]
async fn an_ip_literal_server_verifies_against_its_ip_san() {
    let endpoint = Endpoint::start_for(true, "127.0.0.1").await;
    let proxy = endpoint.adapter(
        endpoint.tls(true, "127.0.0.1"),
        "secret",
        Arc::new(DirectDialer),
    );
    proxy
        .dial_tcp(&destination())
        .await
        .expect("an iPAddress SAN must satisfy an IP-literal server name");
    // The SAN is checked, not merely the chain.
    let mismatched = endpoint.adapter(
        endpoint.tls(true, "127.0.0.2"),
        "secret",
        Arc::new(DirectDialer),
    );
    assert!(mismatched.dial_tcp(&destination()).await.is_err());
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

struct ContextDialer {
    observed: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    inner: Arc<dyn TcpDialer>,
}
#[async_trait]
impl TcpDialer for ContextDialer {
    async fn dial(&self, host: &str, port: u16, internal: bool) -> io::Result<Box<dyn Stream>> {
        self.observed
            .store(if internal { 2 } else { 1 }, Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.dial(host, port, internal).await
    }
}

#[tokio::test]
async fn internally_opened_sessions_mark_front_group_use_for_later_user_streams() {
    for udp_first in [false, true] {
        let endpoint = Endpoint::start(true).await;
        let observed = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let member: Arc<dyn Proxy> = Arc::new(GroupMember(Box::new(DirectAdapter::new())));
        let front = Arc::new(LoadBalanceGroup::new(
            "front",
            vec![member],
            LbStrategy::RoundRobin,
        ));
        let front_proxy: Arc<dyn Proxy> = Arc::<LoadBalanceGroup>::clone(&front);
        let proxy = endpoint.adapter(
            endpoint.tls(true, "localhost"),
            "secret",
            Arc::new(ContextDialer {
                observed: Arc::clone(&observed),
                calls: Arc::clone(&calls),
                inner: Arc::new(ProxyDialer::new(front_proxy)),
            }),
        );
        assert_eq!(front.usage_generation(), 0);
        let mut metadata = destination();
        metadata.internal = true;
        let internal_tcp = if udp_first {
            None
        } else {
            Some(proxy.dial_tcp(&metadata).await.unwrap())
        };
        let internal_udp = if udp_first {
            Some(proxy.dial_udp(&metadata).await.unwrap())
        } else {
            None
        };
        assert_eq!(
            front.usage_generation(),
            1,
            "shared session must record use"
        );
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        metadata.internal = false;
        let mut user = proxy.dial_tcp(&metadata).await.unwrap();
        user.write_all(b"user").await.unwrap();
        let mut reply = [0; 4];
        user.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"user");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "user stream must reuse H2");
        assert_eq!(front.usage_generation(), 1);
        drop((internal_tcp, internal_udp));
    }
}

#[tokio::test]
async fn socket_or_protocol_failure_is_not_a_certificate_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await
            .unwrap();
    });
    let proxy = TrustTunnelAdapter::new(
        "fixture",
        "127.0.0.1",
        addr.port(),
        TlsConfig::new("localhost"),
        Options::new("fixture".into(), "secret".into()),
        false,
        Transport::H2,
        Arc::new(DirectDialer),
    )
    .unwrap();
    let MeowError::Io(error) = proxy.dial_tcp(&destination()).await.err().unwrap() else {
        panic!("expected TLS IO failure")
    };
    assert!(!error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<CertificateVerificationError>));
    assert!(!error.to_string().contains("certificate"));
    peer.await.unwrap();
}

#[tokio::test]
async fn udp_does_not_disclose_process_name() {
    let endpoint = Endpoint::start(true).await;
    let proxy = endpoint.adapter(
        endpoint.tls(true, "localhost"),
        "secret",
        Arc::new(DirectDialer),
    );
    let metadata = Metadata {
        process: "private-browser-profile".into(),
        ..destination()
    };
    let udp = proxy.dial_udp(&metadata).await.unwrap();
    udp.write_packet(b"fixture", &"192.0.2.1:53".parse().unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !endpoint.app_names.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(*endpoint.app_names.lock().unwrap(), vec![Vec::<u8>::new()]);
}

#[tokio::test]
async fn health_check_runs_on_new_session_and_is_not_repeated_on_reuse() {
    let endpoint = Endpoint::start(true).await;
    let mut options = Options::new("fixture".into(), "secret".into());
    options.health_check = true;
    let proxy = TrustTunnelAdapter::new(
        "fixture",
        "127.0.0.1",
        endpoint.addr.port(),
        endpoint.tls(true, "localhost"),
        options,
        false,
        Transport::H2,
        Arc::new(DirectDialer),
    )
    .unwrap();
    for _ in 0..2 {
        let mut stream = proxy.dial_tcp(&destination()).await.unwrap();
        stream.write_all(b"ok").await.unwrap();
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
    }
    assert_eq!(endpoint.checks.load(Ordering::SeqCst), 1);
}

// Proxy groups consume Proxy, while leaf adapters expose ProxyAdapter.
// Keep a thin fixture wrapper to exercise real adapter admission and group use.
struct GroupMember(Box<dyn ProxyAdapter>);
#[async_trait]
impl ProxyAdapter for GroupMember {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn addr(&self) -> &str {
        self.0.addr()
    }
    fn adapter_type(&self) -> meow_common::AdapterType {
        self.0.adapter_type()
    }
    fn support_udp(&self) -> bool {
        self.0.support_udp()
    }
    fn health(&self) -> &meow_common::ProxyHealth {
        self.0.health()
    }
    async fn dial_tcp(
        &self,
        metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
        self.0.dial_tcp(metadata).await
    }
    async fn dial_udp(
        &self,
        metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
        self.0.dial_udp(metadata).await
    }
}
impl meow_common::Proxy for GroupMember {
    fn alive(&self) -> bool {
        self.health().alive()
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        self.alive()
    }
    fn last_delay(&self) -> u16 {
        self.health().last_delay()
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.last_delay()
    }
    fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
        self.health().delay_history()
    }
}

#[tokio::test]
async fn stream_pool_pressure_keeps_load_balance_member_alive() {
    let endpoint = Endpoint::start(true).await;
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.min_streams = 0;
    options.max_streams = 1;
    let adapter = TrustTunnelAdapter::new(
        "fixture",
        "127.0.0.1",
        endpoint.addr.port(),
        endpoint.tls(true, "localhost"),
        options,
        true,
        Transport::H2,
        Arc::new(DirectDialer),
    )
    .unwrap();
    let member: Arc<dyn Proxy> = Arc::new(GroupMember(Box::new(adapter)));
    let group = LoadBalanceGroup::new(
        "balanced",
        vec![Arc::clone(&member)],
        LbStrategy::RoundRobin,
    );
    let held = group.dial_tcp(&destination()).await.unwrap();
    for _ in 0..10 {
        let error = group.dial_tcp(&destination()).await.err().unwrap();
        assert!(error.is_local_resource_error(), "{error}");
        assert!(member.health().alive());
    }
    drop(held);
    group
        .dial_tcp(&destination())
        .await
        .expect("capacity release must restore admission without a probe");
}
