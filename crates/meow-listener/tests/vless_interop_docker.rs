//! Reverse interoperability: pinned xray/mihomo clients in Docker dial this
//! crate's production VLESS Vision listener. The listener runs in-process so
//! the test can assert the listener's raw DIRECT switch counters instead of
//! inferring them from a successful echo.
#![cfg(feature = "listener-vless")]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use meow_common::{Metadata, Network, ProxyAdapter};
use meow_dns::Resolver;
use meow_listener::{
    VlessFallbackLimit, VlessListener, VlessListenerSpec, VlessRealitySpec, VlessSecuritySpec,
    VlessUserSpec,
};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::Socks5Adapter;
use meow_tunnel::Tunnel;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout, Instant};

const IMAGE_XRAY: &str = "ghcr.io/xtls/xray-core:26.3.27";
const IMAGE_MIHOMO: &str = "metacubex/mihomo:v1.19.17";
const CLIENT_SOCKS_PORT: u16 = 1080;
const T: Duration = Duration::from_secs(20);

const VALID_UUID: &str = "11111111-1111-4111-8111-111111111111";
const WRONG_UUID: &str = "22222222-2222-4222-8222-222222222222";
const USER_UUID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const REALITY_PRIVATE: [u8; 32] = [0x42; 32];
const SHORT_ID_HEX: &str = "0123abcd";
const SHORT_ID: [u8; 8] = [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0];

const TLS_INNER_DOMAIN: &str = "tls-inner.test";
const REALITY_INNER_DOMAIN: &str = "reality-inner.test";
const TLS_UDP_DOMAIN: &str = "tls-udp.test";
const REALITY_UDP_DOMAIN: &str = "reality-udp.test";
const WRONG_TCP_DOMAIN: &str = "wrong-tcp.test";
const NOFLOW_TCP_DOMAIN: &str = "noflow-tcp.test";
const OUTER_TLS_NAME: &str = "vision.test";
const REALITY_NAME: &str = "cover.test";

fn docker_required() -> bool {
    std::env::var_os("MEOW_REQUIRE_DOCKER").is_some()
        || std::env::var_os("MIHOMO_REQUIRE_INTEGRATION_BINS").is_some()
}

fn skip_or_panic(reason: impl AsRef<str>) {
    let reason = reason.as_ref();
    assert!(!docker_required(), "{reason}");
    eprintln!("skipping vless reverse docker interop test: {reason}");
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn ensure_image(image: &str) -> Result<(), String> {
    let cached = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if cached {
        return Ok(());
    }
    Command::new("docker")
        .args(["pull", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
        .then_some(())
        .ok_or_else(|| format!("failed to pull docker image {image}"))
}

fn docker_prerequisites() -> Result<(), String> {
    if !docker_available() {
        return Err("docker daemon is not available".into());
    }
    ensure_image(IMAGE_XRAY)?;
    ensure_image(IMAGE_MIHOMO)
}

struct ClientContainer {
    name: String,
    kind: ClientKind,
    tcp_port: u16,
    udp_port: u16,
    _dir: TempDir,
}

impl ClientContainer {
    fn logs(&self) -> String {
        let out = Command::new("docker").args(["logs", &self.name]).output();
        match out {
            Ok(out) => format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => format!("failed to read docker logs: {e}"),
        }
    }

    fn running(&self) -> bool {
        Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", &self.name])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "true")
    }
}

impl Drop for ClientContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientKind {
    Xray,
    Mihomo,
}

impl ClientKind {
    fn label(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::Mihomo => "mihomo",
        }
    }

    fn image(self) -> &'static str {
        match self {
            Self::Xray => IMAGE_XRAY,
            Self::Mihomo => IMAGE_MIHOMO,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Security {
    Tls,
    Reality,
}

impl Security {
    fn label(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Reality => "reality",
        }
    }

    fn inner_domain(self) -> &'static str {
        match self {
            Self::Tls => TLS_INNER_DOMAIN,
            Self::Reality => REALITY_INNER_DOMAIN,
        }
    }

    fn udp_domain(self) -> &'static str {
        match self {
            Self::Tls => TLS_UDP_DOMAIN,
            Self::Reality => REALITY_UDP_DOMAIN,
        }
    }
}

fn parse_published_port(text: &str) -> Result<u16, String> {
    text.lines()
        .next()
        .and_then(|line| line.rsplit(':').next())
        .and_then(|port| port.trim().parse().ok())
        .ok_or_else(|| format!("cannot parse docker port output {text:?}"))
}

fn published_port(name: &str, spec: &str) -> Result<u16, String> {
    let out = Command::new("docker")
        .args(["port", name, spec])
        .output()
        .map_err(|e| format!("docker port {name} {spec}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "docker port {name} {spec} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    parse_published_port(&String::from_utf8_lossy(&out.stdout))
}

struct ClientFixture {
    tls_port: u16,
    reality_port: u16,
    outer_ca_pin: String,
    reality_public_key: String,
}

fn xray_vless_outbound(
    tag: &str,
    port: u16,
    uuid: &str,
    flow: Option<&str>,
    security: &str,
    fixture: &ClientFixture,
) -> Value {
    let mut user = json!({ "id": uuid, "encryption": "none" });
    if let Some(flow) = flow {
        user["flow"] = json!(flow);
    }
    let security_settings = if security == "tls" {
        json!({
            "serverName": OUTER_TLS_NAME,
            "fingerprint": "chrome",
            "pinnedPeerCertSha256": fixture.outer_ca_pin,
            "verifyPeerCertByName": OUTER_TLS_NAME,
        })
    } else {
        json!({
            "serverName": REALITY_NAME,
            "fingerprint": "chrome",
            "publicKey": fixture.reality_public_key,
            "shortId": SHORT_ID_HEX,
            "spiderX": "/",
        })
    };
    let settings_key = if security == "tls" {
        "tlsSettings"
    } else {
        "realitySettings"
    };
    json!({
        "protocol": "vless",
        "tag": tag,
        "settings": {
            "vnext": [{
                "address": "host.docker.internal",
                "port": port,
                "users": [user],
            }],
        },
        "streamSettings": {
            "network": "raw",
            "security": security,
            settings_key: security_settings,
        },
    })
}

fn xray_config(fixture: &ClientFixture) -> Value {
    let tls_port = fixture.tls_port;
    let reality_port = fixture.reality_port;
    let outbounds = vec![
        xray_vless_outbound(
            "vless-tls",
            tls_port,
            VALID_UUID,
            Some("xtls-rprx-vision"),
            "tls",
            fixture,
        ),
        xray_vless_outbound(
            "vless-reality",
            reality_port,
            VALID_UUID,
            Some("xtls-rprx-vision"),
            "reality",
            fixture,
        ),
        xray_vless_outbound(
            "vless-wrong",
            tls_port,
            WRONG_UUID,
            Some("xtls-rprx-vision"),
            "tls",
            fixture,
        ),
        xray_vless_outbound("vless-noflow", tls_port, VALID_UUID, None, "tls", fixture),
    ];
    json!({
        "log": { "loglevel": "debug" },
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": CLIENT_SOCKS_PORT,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true, "ip": "127.0.0.1" },
            "tag": "socks-in",
        }],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                { "type": "field", "domain": ["full:tls-inner.test", "full:tls-udp.test"], "outboundTag": "vless-tls" },
                { "type": "field", "domain": ["full:reality-inner.test", "full:reality-udp.test"], "outboundTag": "vless-reality" },
                { "type": "field", "domain": ["full:wrong-tcp.test"], "outboundTag": "vless-wrong" },
                { "type": "field", "domain": ["full:noflow-tcp.test"], "outboundTag": "vless-noflow" },
            ],
        },
    })
}

fn mihomo_config(fixture: &ClientFixture) -> String {
    let proxy = |name: &str, port: u16, uuid: &str, flow: &str, reality: bool| {
        let mut out = format!(
            "  - name: {name}\n    type: vless\n    server: host.docker.internal\n    port: {port}\n    uuid: \"{uuid}\"\n    udp: true\n    tls: true\n    client-fingerprint: chrome\n"
        );
        if !flow.is_empty() {
            writeln!(out, "    flow: {flow}").unwrap();
        }
        if reality {
            write!(
                out,
                "    servername: {REALITY_NAME}\n    reality-opts:\n      public-key: \"{}\"\n      short-id: \"{SHORT_ID_HEX}\"\n      support-x25519mlkem768: false\n",
                fixture.reality_public_key
            )
            .unwrap();
        } else {
            write!(
                out,
                "    servername: {OUTER_TLS_NAME}\n    fingerprint: \"{}\"\n",
                fixture.outer_ca_pin
            )
            .unwrap();
        }
        out
    };
    format!(
        "log-level: debug\nipv6: false\nmode: rule\nallow-lan: true\nsocks-port: {CLIENT_SOCKS_PORT}\n\nhosts:\n  tls-udp.test: 127.0.0.1\n  reality-udp.test: 127.0.0.1\n\nproxies:\n{}{}{}{}\nrules:\n  - DOMAIN,tls-inner.test,vless-tls\n  - DOMAIN,tls-udp.test,vless-tls\n  - DOMAIN,reality-inner.test,vless-reality\n  - DOMAIN,reality-udp.test,vless-reality\n  - DOMAIN,wrong-tcp.test,vless-wrong\n  - DOMAIN,noflow-tcp.test,vless-noflow\n  - MATCH,vless-tls\n",
        proxy("vless-tls", fixture.tls_port, VALID_UUID, "xtls-rprx-vision", false),
        proxy("vless-reality", fixture.reality_port, VALID_UUID, "xtls-rprx-vision", true),
        proxy("vless-wrong", fixture.tls_port, WRONG_UUID, "xtls-rprx-vision", false),
        proxy("vless-noflow", fixture.tls_port, VALID_UUID, "", false),
    )
}

fn start_client_container(
    kind: ClientKind,
    fixture: &ClientFixture,
) -> Result<ClientContainer, String> {
    static CONTAINERS: AtomicUsize = AtomicUsize::new(0);
    let dir = TempDir::new().map_err(|e| format!("tempdir: {e}"))?;
    let (config_name, contents, args): (&str, String, Vec<String>) = match kind {
        ClientKind::Xray => (
            "config.json",
            xray_config(fixture).to_string(),
            vec!["run".into(), "-c".into(), "/client-config.json".into()],
        ),
        ClientKind::Mihomo => (
            "config.yaml",
            mihomo_config(fixture),
            vec!["-f".into(), "/client-config.yaml".into()],
        ),
    };
    let host_config = dir.path().join(config_name);
    std::fs::write(&host_config, contents).map_err(|e| format!("write client config: {e}"))?;
    let container_config = match kind {
        ClientKind::Xray => "/client-config.json",
        ClientKind::Mihomo => "/client-config.yaml",
    };
    let name = format!(
        "meow-vless-interop-{}-{}-{}",
        kind.label(),
        std::process::id(),
        CONTAINERS.fetch_add(1, Ordering::Relaxed)
    );
    let tcp_spec = format!("127.0.0.1:0:{CLIENT_SOCKS_PORT}/tcp");
    let udp_spec = format!("127.0.0.1:0:{CLIENT_SOCKS_PORT}/udp");
    let mount = format!("{}:{container_config}:ro", host_config.display());
    let mut docker_args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.clone(),
    ];
    if cfg!(target_os = "linux") {
        docker_args.push("--add-host".to_string());
        docker_args.push("host.docker.internal:host-gateway".to_string());
    }
    docker_args.extend([
        "-v".to_string(),
        mount,
        "-p".to_string(),
        tcp_spec,
        "-p".to_string(),
        udp_spec,
        kind.image().to_string(),
    ]);
    docker_args.extend(args);
    let out = Command::new("docker")
        .args(&docker_args)
        .output()
        .map_err(|e| format!("docker run {}: {e}", kind.label()))?;
    if !out.status.success() {
        return Err(format!(
            "docker run {} failed: {}",
            kind.label(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let tcp_port = published_port(&name, &format!("{CLIENT_SOCKS_PORT}/tcp"))?;
    let udp_port = published_port(&name, &format!("{CLIENT_SOCKS_PORT}/udp"))?;
    Ok(ClientContainer {
        name,
        kind,
        tcp_port,
        udp_port,
        _dir: dir,
    })
}

async fn wait_client_ready(client: &ClientContainer) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if !client.running() {
            return Err(format!(
                "{} container exited before its SOCKS inbound was ready\n{}",
                client.kind.label(),
                client.logs()
            ));
        }
        let probe = async {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, client.tcp_port)).await?;
            stream.write_all(&[5, 1, 0]).await?;
            let mut answer = [0u8; 2];
            stream.read_exact(&mut answer).await?;
            Ok::<_, std::io::Error>(answer == [5, 0])
        };
        if matches!(timeout(Duration::from_secs(1), probe).await, Ok(Ok(true))) {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "{} SOCKS inbound never became ready\n{}",
        client.kind.label(),
        client.logs()
    ))
}

fn new_test_ca(common_name: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

struct IssuedCert {
    chain_pem: String,
    key_pem: String,
    chain_ders: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
}

fn issue_cert(ca: &rcgen::Certificate, ca_key: &rcgen::KeyPair, names: Vec<String>) -> IssuedCert {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(names)
        .unwrap()
        .signed_by(&key, ca, ca_key)
        .unwrap();
    let chain_pem = format!("{}{}", cert.pem(), ca.pem());
    IssuedCert {
        chain_pem,
        key_pem: key.serialize_pem(),
        chain_ders: vec![cert.der().clone()],
        key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    }
}

async fn start_tls13_echo(
    names: Vec<String>,
) -> (SocketAddr, CertificateDer<'static>, Arc<AtomicUsize>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca, ca_key) = new_test_ca("meow VLESS inner test CA");
    let issued = issue_cert(&ca, &ca_key, names);
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(issued.chain_ders, issued.key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let task_handshakes = Arc::clone(&handshakes);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let accepted = Arc::clone(&task_handshakes);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                accepted.fetch_add(1, Ordering::Relaxed);
                let (mut rd, mut wr) = tokio::io::split(tls);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    (addr, ca.der().clone(), handshakes)
}

async fn start_tls13_http_cover() -> (SocketAddr, CertificateDer<'static>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca, ca_key) = new_test_ca("meow VLESS cover test CA");
    let issued = issue_cert(&ca, &ca_key, vec![REALITY_NAME.to_string()]);
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(issued.chain_ders, issued.key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 8192 {
                    let Ok(n) = tls.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let body = b"meow reality cover transparent response\n";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    String::from_utf8_lossy(body)
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, ca.der().clone())
}

async fn start_counting_tcp_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            task_accepts.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    (addr, accepts)
}

async fn start_udp_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let datagrams = Arc::new(AtomicUsize::new(0));
    let task_datagrams = Arc::clone(&datagrams);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            task_datagrams.fetch_add(1, Ordering::Relaxed);
            if socket.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    (addr, datagrams)
}

fn tunnel_with_hosts(hosts: &[(&str, IpAddr)]) -> Tunnel {
    let mut trie = meow_trie::DomainTrie::new();
    for (name, ip) in hosts {
        trie.insert(name, vec![*ip].into());
    }
    let resolver = Arc::new(Resolver::new(
        vec!["127.0.0.1:9".parse().unwrap()],
        vec![],
        meow_common::DnsMode::Normal,
        trie,
        true,
        true,
    ));
    let tunnel = Tunnel::new(Arc::clone(&resolver));
    let slot = meow_dns::new_resolver_slot(resolver);
    let res = meow_config::rebuild_from_raw_with_resolver(
        &Default::default(),
        Some(&slot),
        None,
        &HashMap::new(),
        None,
        &meow_proxy::SelectionBacking::unpersisted(),
    )
    .unwrap();
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
        "DIRECT",
    ))]);
    tunnel
}

fn tls_spec(certificate: String, private_key: String) -> VlessListenerSpec {
    VlessListenerSpec {
        users: vec![VlessUserSpec {
            username: "alice".into(),
            uuid: USER_UUID,
        }],
        security: VlessSecuritySpec::StandardTls {
            certificate,
            private_key,
            alpn: vec![],
        },
        udp: true,
    }
}

fn reality_spec(dest: String) -> VlessListenerSpec {
    VlessListenerSpec {
        users: vec![VlessUserSpec {
            username: "alice".into(),
            uuid: USER_UUID,
        }],
        security: VlessSecuritySpec::Reality(VlessRealitySpec {
            dest,
            private_key: REALITY_PRIVATE,
            short_ids: vec![SHORT_ID],
            server_names: vec![REALITY_NAME.into()],
            max_time_difference_us: 120_000_000,
            limit_fallback_upload: VlessFallbackLimit::default(),
            limit_fallback_download: VlessFallbackLimit::default(),
        }),
        udp: true,
    }
}

async fn start_vless_listener(
    spec: VlessListenerSpec,
    tunnel: Tunnel,
    name: &str,
) -> (u16, Arc<VlessListener>) {
    let listener = Arc::new(VlessListener::new(tunnel, name.into(), spec).unwrap());
    let socket = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let task_listener = Arc::clone(&listener);
    tokio::spawn(async move {
        let _ = task_listener.run_on(socket).await;
    });
    (port, listener)
}

fn metadata_domain(domain: &str, port: u16, network: Network) -> Metadata {
    Metadata {
        network,
        host: domain.into(),
        dst_port: port,
        ..Default::default()
    }
}

fn socks_adapter(client: &ClientContainer) -> Socks5Adapter {
    Socks5Adapter::new(
        "docker-client-socks",
        "127.0.0.1",
        client.tcp_port,
        None,
        false,
        false,
        Arc::new(DirectDialer),
    )
}

fn patterned(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ seed.wrapping_mul(31))
        .collect()
}

async fn bulk_echo<S>(mut conn: S, payload: &[u8], context: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(&mut conn);
    let write = async {
        wr.write_all(payload).await?;
        wr.flush().await
    };
    let read = async {
        let mut echoed = vec![0u8; payload.len()];
        rd.read_exact(&mut echoed).await.map(|_| echoed)
    };
    let (written, echoed) = timeout(T, async { tokio::join!(write, read) })
        .await
        .unwrap_or_else(|_| panic!("{context}: bulk echo timed out"));
    written.unwrap_or_else(|e| panic!("{context}: bulk write failed: {e}"));
    let echoed = echoed.unwrap_or_else(|e| panic!("{context}: bulk read failed: {e}"));
    assert!(
        echoed == payload,
        "{context}: bulk echo corrupted the payload"
    );
}

async fn positive_tcp(
    client: &ClientContainer,
    security: Security,
    listener: &Arc<VlessListener>,
    echo: SocketAddr,
    echo_ca: &CertificateDer<'static>,
    echo_handshakes: &AtomicUsize,
) {
    let adapter = socks_adapter(client);
    let domain = security.inner_domain();
    let before = listener.vision_raw_switch_counts();
    let outer = timeout(
        T,
        adapter.dial_tcp(&metadata_domain(domain, echo.port(), Network::Tcp)),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{} {}: SOCKS dial timeout\n{}",
            client.kind.label(),
            security.label(),
            client.logs()
        )
    })
    .unwrap_or_else(|e| {
        panic!(
            "{} {}: SOCKS dial failed: {e}\n{}",
            client.kind.label(),
            security.label(),
            client.logs()
        )
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(echo_ca.clone()).unwrap();
    let inner_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(inner_cfg));
    let server_name = ServerName::try_from(domain).unwrap();
    let inner = timeout(T, connector.connect(server_name, outer))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{} {}: inner TLS timeout\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            )
        })
        .unwrap_or_else(|e| {
            panic!(
                "{} {}: inner TLS failed: {e}\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            )
        });
    assert_eq!(
        inner.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    // xray only enters its Vision DIRECT write mode on a complete TLS record
    // at the start of a SOCKS read batch. Wait until the inner server has
    // accepted the handshake — that proves the client's CCS/Finished flight
    // has already been consumed — then make the first application write a
    // small, isolated record before the bulk transfer.
    let accepted_before = echo_handshakes.load(Ordering::Relaxed);
    let accept_deadline = Instant::now() + Duration::from_secs(5);
    while echo_handshakes.load(Ordering::Relaxed) == accepted_before {
        if Instant::now() >= accept_deadline {
            panic!(
                "{} {}: inner TLS server never completed the handshake",
                client.kind.label(),
                security.label()
            );
        }
        sleep(Duration::from_millis(10)).await;
    }
    let mut inner = inner;
    let prime = *b"prime";
    timeout(T, inner.write_all(&prime))
        .await
        .expect("prime write timeout")
        .expect("prime write");
    timeout(T, inner.flush())
        .await
        .expect("prime flush timeout")
        .expect("prime flush");
    let mut prime_echo = [0u8; 5];
    timeout(T, inner.read_exact(&mut prime_echo))
        .await
        .expect("prime echo timeout")
        .expect("prime echo");
    assert_eq!(prime_echo, prime, "prime echo corrupted");

    let payload = patterned(
        (1 << 20) + 777,
        if security == Security::Tls { 7 } else { 8 },
    );
    let size = payload.len() + prime.len();
    let context = format!("{} {}", client.kind.label(), security.label());
    bulk_echo(inner, &payload, &context).await;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let now = listener.vision_raw_switch_counts();
        if now.0 > before.0 && now.1 > before.1 {
            assert_eq!(
                (now.0 - before.0, now.1 - before.1),
                (1, 1),
                "{} {}: exactly one Vision TCP connection must switch each direction raw",
                client.kind.label(),
                security.label()
            );
            eprintln!(
                "interop evidence: {} {} tcp echo {size} B each way; vision raw switches +{} read/+{} write",
                client.kind.label(),
                security.label(),
                now.0 - before.0,
                now.1 - before.1
            );
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "{} {}: DIRECT switch counters stayed at {now:?} from {before:?}\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
}

#[derive(Debug)]
enum SocksUdpAddr {
    Ipv4(Ipv4Addr),
    Domain(String),
}

#[derive(Debug)]
struct SocksUdpSource {
    addr: SocksUdpAddr,
    port: u16,
}

struct SocksUdpAssociation {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

impl SocksUdpAssociation {
    async fn connect(client: &ClientContainer) -> std::io::Result<Self> {
        let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, client.tcp_port)).await?;
        control.write_all(&[5, 1, 0]).await?;
        let mut answer = [0u8; 2];
        control.read_exact(&mut answer).await?;
        if answer != [5, 0] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SOCKS no-auth refused",
            ));
        }
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut head = [0u8; 4];
        control.read_exact(&mut head).await?;
        if head[1] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("UDP ASSOCIATE reply {}", head[1]),
            ));
        }
        read_socks_addr_tcp(&mut control, head[3]).await?;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client.udp_port);
        Ok(Self {
            _control: control,
            socket,
            relay,
        })
    }

    async fn send_domain(&self, domain: &str, port: u16, payload: &[u8]) -> std::io::Result<()> {
        assert!(domain.len() <= 255);
        let mut packet = Vec::with_capacity(domain.len() + payload.len() + 7);
        packet.extend_from_slice(&[0, 0, 0, 3, domain.len() as u8]);
        packet.extend_from_slice(domain.as_bytes());
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(payload);
        self.socket.send_to(&packet, self.relay).await?;
        Ok(())
    }

    async fn recv(&self) -> std::io::Result<(Vec<u8>, SocksUdpSource)> {
        let mut buf = vec![0u8; 65536];
        let (n, _) = self.socket.recv_from(&mut buf).await?;
        parse_socks_udp_datagram(&buf[..n]).map_err(std::io::Error::other)
    }
}

async fn read_socks_addr_tcp(stream: &mut TcpStream, atyp: u8) -> std::io::Result<()> {
    let len = match atyp {
        1 => 4,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        4 => 16,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad SOCKS atyp",
            ))
        }
    };
    let mut discard = vec![0u8; len + 2];
    stream.read_exact(&mut discard).await.map(|_| ())
}

fn parse_socks_udp_datagram(packet: &[u8]) -> Result<(Vec<u8>, SocksUdpSource), String> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return Err("malformed SOCKS UDP header or nonzero fragment".into());
    }
    let atyp = packet[3];
    let (addr, used) = match atyp {
        1 => {
            if packet.len() < 4 + 4 + 2 {
                return Err("truncated IPv4 SOCKS UDP address".into());
            }
            (
                SocksUdpAddr::Ipv4(Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7])),
                4 + 4 + 2,
            )
        }
        3 => {
            let len = usize::from(*packet.get(4).ok_or("missing domain length")?);
            let end = 5 + len;
            if packet.len() < end + 2 {
                return Err("truncated domain SOCKS UDP address".into());
            }
            let domain = std::str::from_utf8(&packet[5..end])
                .map_err(|_| "non-UTF8 domain in SOCKS UDP reply")?
                .to_string();
            (SocksUdpAddr::Domain(domain), end + 2)
        }
        other => return Err(format!("unsupported SOCKS UDP atyp {other}")),
    };
    let port = u16::from_be_bytes([packet[used - 2], packet[used - 1]]);
    if packet.len() <= used {
        return Err("SOCKS UDP datagram carries no payload".into());
    }
    Ok((packet[used..].to_vec(), SocksUdpSource { addr, port }))
}

async fn positive_udp(client: &ClientContainer, security: Security, echo: SocketAddr) {
    let association = timeout(T, SocksUdpAssociation::connect(client))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{} {}: UDP associate timeout\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            )
        })
        .unwrap_or_else(|e| {
            panic!(
                "{} {}: UDP associate failed: {e}\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            )
        });
    let domain = security.udp_domain();
    let payloads = [patterned(21, 21), patterned(300, 22), patterned(1400, 23)];
    for payload in &payloads {
        timeout(T, association.send_domain(domain, echo.port(), payload))
            .await
            .expect("UDP send timeout")
            .expect("UDP send");
    }
    let mut replies = HashMap::new();
    for _ in 0..payloads.len() {
        let (payload, source) = timeout(T, association.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} {}: UDP echo timeout\n{}",
                    client.kind.label(),
                    security.label(),
                    client.logs()
                )
            })
            .expect("UDP receive");
        replies.insert(payload, source);
    }
    for expected in &payloads {
        let source = replies.get(expected).unwrap_or_else(|| {
            panic!(
                "{} {}: missing UDP echo of {} B",
                client.kind.label(),
                security.label(),
                expected.len()
            )
        });
        assert_eq!(
            source.port,
            echo.port(),
            "{} {}: UDP reply source port",
            client.kind.label(),
            security.label()
        );
        match client.kind {
            ClientKind::Xray => assert!(
                matches!(&source.addr, SocksUdpAddr::Domain(name) if name == domain),
                "{} {}: xray must report the domain reply source, got {:?}",
                client.kind.label(),
                security.label(),
                source.addr
            ),
            ClientKind::Mihomo => assert!(
                matches!(&source.addr, SocksUdpAddr::Ipv4(ip) if *ip == Ipv4Addr::LOCALHOST),
                "{} {}: mihomo resolves UDP before VLESS and must report the echo IP, got {:?}",
                client.kind.label(),
                security.label(),
                source.addr
            ),
        }
    }
    eprintln!(
        "interop evidence: {} {} xudp echo datagrams {:?} B, sources {:?}",
        client.kind.label(),
        security.label(),
        payloads.iter().map(Vec::len).collect::<Vec<_>>(),
        replies.values().collect::<Vec<_>>()
    );
}

async fn negative_tcp(
    client: &ClientContainer,
    domain: &'static str,
    echo: SocketAddr,
    accepts: &AtomicUsize,
    label: &str,
) {
    let before = accepts.load(Ordering::Relaxed);
    let adapter = socks_adapter(client);
    let outcome = timeout(
        T,
        adapter.dial_tcp(&metadata_domain(domain, echo.port(), Network::Tcp)),
    )
    .await;
    if let Ok(Ok(mut conn)) = outcome {
        let _ = timeout(T, conn.write_all(b"must never echo")).await;
        let _ = timeout(T, conn.flush()).await;
        let mut byte = [0u8; 1];
        match timeout(Duration::from_secs(5), conn.read(&mut byte)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!(
                "{} {label}: rejected flow produced {n} application bytes\n{}",
                client.kind.label(),
                client.logs()
            ),
            Err(_) => panic!(
                "{} {label}: rejected flow did not close\n{}",
                client.kind.label(),
                client.logs()
            ),
        }
    }
    sleep(Duration::from_millis(250)).await;
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        before,
        "{} {label}: rejected VLESS request must not dial the target",
        client.kind.label()
    );
    eprintln!(
        "interop evidence: {} {label} rejected silently, no target dial",
        client.kind.label()
    );
}

async fn reality_cover_https(reality_port: u16, cover_ca: &CertificateDer<'static>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cover_ca.clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let raw = TcpStream::connect((Ipv4Addr::LOCALHOST, reality_port))
        .await
        .unwrap();
    let mut tls = timeout(
        T,
        connector.connect(ServerName::try_from(REALITY_NAME).unwrap(), raw),
    )
    .await
    .expect("cover TLS handshake timeout")
    .expect("cover TLS handshake");
    let request =
        format!("GET /interop HTTP/1.1\r\nHost: {REALITY_NAME}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let mut response = Vec::new();
    timeout(T, tls.read_to_end(&mut response))
        .await
        .expect("cover response timeout")
        .expect("cover response read");
    let text = String::from_utf8(response).unwrap();
    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\n"),
        "cover response head: {text:?}"
    );
    assert!(
        text.ends_with("meow reality cover transparent response\n"),
        "cover response body: {text:?}"
    );
    eprintln!("interop evidence: ordinary TLS client relayed to REALITY cover with byte-exact HTTPS-ish response");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_vless_vision_interop_matrix() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    if let Err(reason) = docker_prerequisites() {
        skip_or_panic(reason);
        return;
    }

    let (inner_echo, inner_ca, inner_handshakes) = start_tls13_echo(vec![
        TLS_INNER_DOMAIN.to_string(),
        REALITY_INNER_DOMAIN.to_string(),
    ])
    .await;
    let (udp_echo, _udp_datagrams) = start_udp_echo().await;
    let (negative_echo, negative_accepts) = start_counting_tcp_echo().await;
    let (cover, cover_ca) = start_tls13_http_cover().await;

    let tunnel = tunnel_with_hosts(&[
        (TLS_INNER_DOMAIN, inner_echo.ip()),
        (REALITY_INNER_DOMAIN, inner_echo.ip()),
        (TLS_UDP_DOMAIN, udp_echo.ip()),
        (REALITY_UDP_DOMAIN, udp_echo.ip()),
        (WRONG_TCP_DOMAIN, negative_echo.ip()),
        (NOFLOW_TCP_DOMAIN, negative_echo.ip()),
    ]);

    let (outer_ca, outer_ca_key) = new_test_ca("meow VLESS outer test CA");
    let outer = issue_cert(&outer_ca, &outer_ca_key, vec![OUTER_TLS_NAME.to_string()]);
    let outer_ca_pin = hex::encode(Sha256::digest(outer_ca.der().as_ref()));
    let (tls_port, tls_listener) = start_vless_listener(
        tls_spec(outer.chain_pem, outer.key_pem),
        tunnel.clone(),
        "interop-vless-tls",
    )
    .await;
    let (reality_port, reality_listener) = start_vless_listener(
        reality_spec(format!("{}:{}", cover.ip(), cover.port())),
        tunnel,
        "interop-vless-reality",
    )
    .await;

    let reality_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(REALITY_PRIVATE));
    let fixture = ClientFixture {
        tls_port,
        reality_port,
        outer_ca_pin,
        reality_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(reality_public.as_bytes()),
    };

    let xray = start_client_container(ClientKind::Xray, &fixture)
        .unwrap_or_else(|e| panic!("xray client setup failed: {e}"));
    wait_client_ready(&xray)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mihomo = start_client_container(ClientKind::Mihomo, &fixture)
        .unwrap_or_else(|e| panic!("mihomo client setup failed: {e}"));
    wait_client_ready(&mihomo)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    for client in [&xray, &mihomo] {
        for (security, listener) in [
            (Security::Tls, &tls_listener),
            (Security::Reality, &reality_listener),
        ] {
            positive_tcp(
                client,
                security,
                listener,
                inner_echo,
                &inner_ca,
                &inner_handshakes,
            )
            .await;
            positive_udp(client, security, udp_echo).await;
        }
        negative_tcp(
            client,
            WRONG_TCP_DOMAIN,
            negative_echo,
            &negative_accepts,
            "wrong-uuid",
        )
        .await;
        negative_tcp(
            client,
            NOFLOW_TCP_DOMAIN,
            negative_echo,
            &negative_accepts,
            "missing-flow",
        )
        .await;
    }

    reality_cover_https(reality_port, &cover_ca).await;
}
