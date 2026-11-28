use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

#[path = "../tests/common/reality_t5_target.rs"]
mod reality_t5_target;

const PLAIN_TCP: u16 = 10080;
const SERVER_FIRST_TCP: u16 = 10025;
const TLS13_TCP: u16 = 10113;
const TLS12_TCP: u16 = 10112;
const UDP_A: u16 = 10053;
const UDP_B: u16 = 10054;
const UDP_443: u16 = 443;

#[derive(Clone, Copy)]
enum TcpService {
    Echo,
    ServerFirst,
}

fn arg_value(name: &str) -> String {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == name {
            return args
                .next()
                .unwrap_or_else(|| panic!("missing value for {name}"));
        }
    }
    panic!("missing required argument {name}");
}

fn pem_sections(path: &str) -> Vec<(String, Vec<u8>)> {
    let text = std::fs::read_to_string(path).expect("read PEM file");
    let mut sections = Vec::new();
    let mut label: Option<String> = None;
    let mut encoded = String::new();
    for line in text.lines().map(str::trim) {
        if let Some(name) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
        {
            assert!(label.is_none(), "nested PEM section in {path}");
            label = Some(name.to_string());
            encoded.clear();
        } else if let Some(name) = line
            .strip_prefix("-----END ")
            .and_then(|s| s.strip_suffix("-----"))
        {
            let open = label.take().expect("END without BEGIN");
            assert_eq!(open, name, "mismatched PEM labels in {path}");
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .expect("decode PEM base64");
            sections.push((name.to_string(), bytes));
            encoded.clear();
        } else if label.is_some() {
            encoded.push_str(line);
        }
    }
    assert!(label.is_none(), "unterminated PEM section in {path}");
    sections
}

fn load_cert_chain(path: &str) -> Vec<CertificateDer<'static>> {
    let certs = pem_sections(path)
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, bytes)| CertificateDer::from(bytes))
        .collect::<Vec<_>>();
    assert!(
        !certs.is_empty(),
        "certificate file contains no certificate"
    );
    certs
}

fn load_key(path: &str) -> PrivateKeyDer<'static> {
    let (label, bytes) = pem_sections(path)
        .into_iter()
        .find(|(label, _)| label.ends_with("PRIVATE KEY"))
        .expect("private key file contains no key");
    match label.as_str() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes)),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(bytes)),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(bytes)),
        other => panic!("unsupported private key PEM label {other}"),
    }
}

async fn echo_copy(stream: TcpStream, server_first: bool) {
    let (mut rd, mut wr) = stream.into_split();
    if server_first && wr.write_all(b"220 docker target ready\r\n").await.is_err() {
        return;
    }
    let _ = tokio::io::copy(&mut rd, &mut wr).await;
}

async fn tcp_plain_listener(listener: TcpListener, service: TcpService) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(echo_copy(
                    stream,
                    matches!(service, TcpService::ServerFirst),
                ));
            }
            Err(e) => {
                eprintln!("tcp accept failed: {e}");
                return;
            }
        }
    }
}

async fn tcp_tls_listener(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        let (mut rd, mut wr) = tokio::io::split(tls);
                        let _ = tokio::io::copy(&mut rd, &mut wr).await;
                    }
                });
            }
            Err(e) => {
                eprintln!("tls tcp accept failed: {e}");
                return;
            }
        }
    }
}

async fn bind_tcp(port: u16, service: TcpService) {
    for ip in [Ipv6Addr::UNSPECIFIED.into(), Ipv4Addr::UNSPECIFIED.into()] {
        let addr = SocketAddr::new(ip, port);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                tokio::spawn(tcp_plain_listener(listener, service));
            }
            Err(e) => eprintln!("tcp bind {addr} failed: {e}"),
        }
    }
}

async fn bind_tls_tcp(port: u16, acceptor: tokio_rustls::TlsAcceptor) {
    for ip in [Ipv6Addr::UNSPECIFIED.into(), Ipv4Addr::UNSPECIFIED.into()] {
        let addr = SocketAddr::new(ip, port);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                tokio::spawn(tcp_tls_listener(listener, acceptor.clone()));
            }
            Err(e) => eprintln!("tls tcp bind {addr} failed: {e}"),
        }
    }
}

async fn udp_echo(socket: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                if socket.send_to(&buf[..n], peer).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                eprintln!("udp recv failed: {e}");
                return;
            }
        }
    }
}

async fn bind_udp(port: u16) {
    for ip in [Ipv6Addr::UNSPECIFIED.into(), Ipv4Addr::UNSPECIFIED.into()] {
        let addr = SocketAddr::new(ip, port);
        match UdpSocket::bind(addr).await {
            Ok(socket) => {
                tokio::spawn(udp_echo(Arc::new(socket)));
            }
            Err(e) => eprintln!("udp bind {addr} failed: {e}"),
        }
    }
}

async fn probe_connect(ip: IpAddr, port: u16) {
    let outcome = timeout(Duration::from_secs(2), TcpStream::connect((ip, port))).await;
    match outcome {
        Ok(Ok(_)) => println!("probe-connect-success {ip}:{port}"),
        Ok(Err(e)) => println!("probe-connect-failure {ip}:{port}: {e}"),
        Err(_) => println!("probe-connect-failure {ip}:{port}: timed out"),
    }
}

fn tap_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn tap_append(dst: &mut Vec<u8>, bytes: &[u8]) {
    let take = (96 * 1024usize).saturating_sub(dst.len()).min(bytes.len());
    dst.extend_from_slice(&bytes[..take]);
}

async fn serve_tap(listen_port: u16, target: SocketAddr, snapshot_at: usize) {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, listen_port))
        .await
        .unwrap_or_else(|e| panic!("tap bind {listen_port}: {e}"));
    println!("t5 tap ready listen={listen_port}");
    let mut next = 0usize;
    while let Ok((client, _)) = listener.accept().await {
        next += 1;
        let connection = next;
        tokio::spawn(async move {
            let Ok(server) = TcpStream::connect(target).await else {
                eprintln!("t5 tap connect {target} failed");
                return;
            };
            let c2s = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let s2c = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let snapshot_sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let print_snapshot =
                |connection: usize,
                 c2s: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
                 s2c: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>| {
                    println!(
                    "t5-tap-stream {{\"connection\":{connection},\"c2s_hex\":\"{}\",\"s2c_hex\":\"{}\"}}",
                    tap_hex(&c2s.lock().unwrap()),
                    tap_hex(&s2c.lock().unwrap())
                );
                };
            let (mut crd, mut cwr) = tokio::io::split(client);
            let (mut srd, mut swr) = tokio::io::split(server);
            let down = tokio::spawn({
                let c2s = std::sync::Arc::clone(&c2s);
                let s2c = std::sync::Arc::clone(&s2c);
                let snapshot_sent = std::sync::Arc::clone(&snapshot_sent);
                async move {
                    let mut buf = [0u8; 8192];
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut srd, &mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                tap_append(&mut s2c.lock().unwrap(), &buf[..n]);
                                if tokio::io::AsyncWriteExt::write_all(&mut cwr, &buf[..n])
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                if s2c.lock().unwrap().len() >= snapshot_at
                                    && !snapshot_sent
                                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                                {
                                    println!(
                                        "t5-tap-stream {{\"connection\":{connection},\"c2s_hex\":\"{}\",\"s2c_hex\":\"{}\"}}",
                                        tap_hex(&c2s.lock().unwrap()),
                                        tap_hex(&s2c.lock().unwrap())
                                    );
                                }
                            }
                        }
                    }
                }
            });
            let mut buf = [0u8; 8192];
            loop {
                match tokio::io::AsyncReadExt::read(&mut crd, &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        tap_append(&mut c2s.lock().unwrap(), &buf[..n]);
                        if tokio::io::AsyncWriteExt::write_all(&mut swr, &buf[..n])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            down.abort();
            if !snapshot_sent.load(std::sync::atomic::Ordering::Relaxed) {
                print_snapshot(connection, &c2s, &s2c);
            }
        });
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--probe-connect") {
        assert!(args.len() == 3, "usage: --probe-connect <ip> <port>");
        let ip = args[1].parse::<IpAddr>().expect("probe IP");
        let port = args[2].parse::<u16>().expect("probe port");
        probe_connect(ip, port).await;
        return;
    }

    if args.first().is_some_and(|arg| arg == "--tap") {
        assert!(
            args.len() == 4,
            "usage: --tap <listen-port> <target-ip:port> <snapshot-at>"
        );
        let listen_port = args[1].parse::<u16>().expect("tap listen port");
        let target = args[2].parse::<SocketAddr>().expect("tap target address");
        let snapshot_at = args[3].parse::<usize>().expect("tap snapshot byte count");
        serve_tap(listen_port, target, snapshot_at).await;
        return;
    }

    let cert_path = arg_value("--cert");
    let key_path = arg_value("--key");
    let chain = load_cert_chain(&cert_path);
    let key = load_key(&key_path);
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls13 = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(chain.clone(), key.clone_key())
        .expect("TLS 1.3 target config");
    let tls12 = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("TLS 1.2 target config");

    bind_tcp(PLAIN_TCP, TcpService::Echo).await;
    bind_tcp(SERVER_FIRST_TCP, TcpService::ServerFirst).await;
    bind_tls_tcp(TLS13_TCP, tokio_rustls::TlsAcceptor::from(Arc::new(tls13))).await;
    bind_tls_tcp(TLS12_TCP, tokio_rustls::TlsAcceptor::from(Arc::new(tls12))).await;
    bind_udp(UDP_A).await;
    bind_udp(UDP_B).await;
    bind_udp(UDP_443).await;
    for (port, spec) in reality_t5_target::docker_t5_specs() {
        for ip in [Ipv6Addr::UNSPECIFIED.into(), Ipv4Addr::UNSPECIFIED.into()] {
            let addr = SocketAddr::new(ip, port);
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    tokio::spawn(reality_t5_target::bind_t5_target(listener, port, spec));
                }
                Err(e) => eprintln!("t5 target bind {addr} failed: {e}"),
            }
        }
    }

    println!(
        "target ready tcp={PLAIN_TCP},{SERVER_FIRST_TCP},{TLS13_TCP},{TLS12_TCP} udp={UDP_A},{UDP_B},{UDP_443}"
    );
    std::future::pending::<()>().await;
}
