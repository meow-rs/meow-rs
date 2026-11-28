//! REALITY v2 T6 acceptance through the real `meow` binary entrypoint.
#![cfg(feature = "listener-vless")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::{TransportChain, VlessAdapter, VlessFlow};
use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

const T: Duration = Duration::from_secs(10);
const ALICE: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const ALICE_UUID: &str = "11111111-1111-4111-8111-111111111111";
const REALITY_PRIVATE_B64: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
const REALITY_PUBLIC_B64: &str = "EyxEK-AQ-9V-cmAzKKp25x_MwVA6riGTJ9FNnJmT9HI";
const SHORT_ID_HEX: &str = "0123abcd00000000";
const SHORT_ID: [u8; 8] = [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0];

fn metadata(addr: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Tcp,
        host: addr.ip().to_string().into(),
        dst_port: addr.port(),
        ..Default::default()
    }
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

fn spawn_meow(config: &std::path::Path, cwd: &std::path::Path) -> tokio::process::Child {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"));
    child
        .arg("-f")
        .arg(config)
        .arg("-d")
        .arg(cwd)
        .current_dir(cwd)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        child.env_remove(variable);
    }
    child.spawn().expect("spawn meow")
}

async fn wait_api(port: u16, child: &mut tokio::process::Child) {
    let ready = timeout(Duration::from_secs(15), async {
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(40)).await;
        }
    })
    .await;
    if ready.is_err() {
        let _ = child.kill().await;
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr).await;
        }
        panic!("meow did not start within 15s; stderr: {stderr}");
    }
}

fn runtime_yaml(
    listener_port: u16,
    api_port: u16,
    target: SocketAddr,
    mimic_block: &str,
) -> String {
    format!(
        "mode: rule\nlog-level: warn\nipv6: false\nallow-lan: false\ndns: {{enable: false}}\nexternal-controller: '127.0.0.1:{api_port}'\nlisteners:\n  - name: vision-in\n    type: vless\n    listen: 127.0.0.1\n    port: {listener_port}\n    reality-config:\n      dest: \"{}:{}\"\n      private-key: \"{REALITY_PRIVATE_B64}\"\n      short-id: [\"{SHORT_ID_HEX}\"]\n      server-names: [\"localhost\"]\n{mimic_block}    users:\n      - username: alice\n        uuid: \"{ALICE_UUID}\"\n        flow: xtls-rprx-vision\nrules:\n  - MATCH,DIRECT\n",
        target.ip(),
        target.port(),
    )
}

async fn start_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}

fn vision_reality_adapter(port: u16) -> VlessAdapter {
    use base64::Engine as _;
    let public_key: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(REALITY_PUBLIC_B64)
        .unwrap()
        .try_into()
        .unwrap();
    let tls = TlsConfig {
        reality: Some(RealityConfig {
            public_key,
            short_id: SHORT_ID,
            support_x25519_mlkem768: false,
            protocol_clock: None,
        }),
        ..TlsConfig::new("localhost")
    };
    let mut chain = TransportChain::empty();
    chain.push(Box::new(TlsLayer::new(&tls).expect("REALITY TLS layer")));
    VlessAdapter::new(
        "t6-client",
        "127.0.0.1",
        port,
        ALICE,
        Some(VlessFlow::XtlsRprxVision),
        true,
        chain,
        Arc::new(DirectDialer),
    )
}

async fn adapter_echo(adapter: &VlessAdapter, target: SocketAddr, payload: &[u8]) {
    let mut conn = timeout(T, adapter.dial_tcp(&metadata(target)))
        .await
        .expect("client dial timeout")
        .expect("client REALITY/VLESS dial");
    timeout(T, async {
        conn.write_all(payload).await.expect("client write");
        conn.flush().await.expect("client flush");
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.expect("client echo read");
        assert_eq!(got, payload);
    })
    .await
    .expect("client echo timeout");
}

const MIRRORED_ENCRYPTED_RECORD_LENS: [u16; 4] = [25, 3217, 281, 69];

fn mimic_flight(session_id: &[u8]) -> Vec<u8> {
    fn ext(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }
    let share_secret = x25519_dalek::StaticSecret::from([9u8; 32]);
    let share = x25519_dalek::PublicKey::from(&share_secret).to_bytes();
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&[0x03, 0x03]);
    sh_body.extend_from_slice(&[0x66; 32]);
    sh_body.push(u8::try_from(session_id.len()).expect("TLS session id length"));
    sh_body.extend_from_slice(session_id);
    sh_body.extend_from_slice(&0x1301u16.to_be_bytes());
    sh_body.push(0);
    let versions = ext(0x002b, &0x0304u16.to_be_bytes());
    let mut key_share_body = Vec::new();
    key_share_body.extend_from_slice(&0x001du16.to_be_bytes());
    key_share_body.extend_from_slice(&(share.len() as u16).to_be_bytes());
    key_share_body.extend_from_slice(&share);
    let key_share = ext(0x0033, &key_share_body);
    let mut exts = Vec::new();
    exts.extend_from_slice(&versions);
    exts.extend_from_slice(&key_share);
    sh_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    sh_body.extend_from_slice(&exts);
    let mut sh = vec![0x02];
    sh.extend_from_slice(&(sh_body.len() as u32).to_be_bytes()[1..4]);
    sh.extend_from_slice(&sh_body);

    let mut flight = Vec::new();
    flight.extend_from_slice(&[0x16, 0x03, 0x03]);
    flight.extend_from_slice(&(sh.len() as u16).to_be_bytes());
    flight.extend_from_slice(&sh);
    flight.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    for len in MIRRORED_ENCRYPTED_RECORD_LENS {
        flight.extend_from_slice(&[0x17, 0x03, 0x03]);
        flight.extend_from_slice(&len.to_be_bytes());
        flight.resize(flight.len() + usize::from(len), 0x5a);
    }
    flight
}

#[derive(Default)]
struct MimicTargetState {
    tcp_accepts: usize,
    target_closes: usize,
    preflight_parses: usize,
    uploaded_ch_records: Vec<Vec<u8>>,
    server_flights: Vec<Vec<u8>>,
}

async fn serve_mimic_target_connection(mut stream: TcpStream, state: Arc<Mutex<MimicTargetState>>) {
    let mut head = [0u8; 5];
    if stream.read_exact(&mut head).await.is_err() {
        return;
    }
    let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let mut body = vec![0u8; len];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }
    let mut first = head.to_vec();
    first.extend_from_slice(&body);
    if first.len() >= 5 + 39 && first[0] == 0x16 && first[5] == 0x01 {
        let session_id_len = usize::from(first[5 + 38]);
        if session_id_len <= 32 && first.len() >= 5 + 39 + session_id_len {
            let session_id = first[5 + 39..5 + 39 + session_id_len].to_vec();
            let flight = {
                let mut locked = state.lock().unwrap();
                locked.preflight_parses += 1;
                locked.uploaded_ch_records.push(first.clone());
                mimic_flight(&session_id)
            };
            if stream.write_all(&flight).await.is_ok() {
                state.lock().unwrap().server_flights.push(flight);
                let _ = stream.flush().await;
            }
        }
    }
    let mut sink = [0u8; 1024];
    loop {
        match stream.read(&mut sink).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

async fn start_counting_mimic_target(
) -> (SocketAddr, Arc<AtomicUsize>, Arc<Mutex<MimicTargetState>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let early_dials = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(Mutex::new(MimicTargetState::default()));
    tokio::spawn({
        let early_dials = Arc::clone(&early_dials);
        let state = Arc::clone(&state);
        async move {
            while let Ok((stream, _)) = listener.accept().await {
                early_dials.fetch_add(1, Ordering::SeqCst);
                state.lock().unwrap().tcp_accepts += 1;
                tokio::spawn({
                    let state = Arc::clone(&state);
                    async move {
                        serve_mimic_target_connection(stream, Arc::clone(&state)).await;
                        state.lock().unwrap().target_closes += 1;
                    }
                });
            }
        }
    });
    (addr, early_dials, state)
}

#[derive(Default)]
struct WireTapStream {
    client_to_server: Vec<u8>,
    server_to_client: Vec<u8>,
}

fn append_tap_bytes(captured: &mut Vec<u8>, bytes: &[u8]) {
    const CAP: usize = 64 * 1024;
    let take = CAP.saturating_sub(captured.len()).min(bytes.len());
    captured.extend_from_slice(&bytes[..take]);
}

async fn start_wire_tap(server: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<WireTapStream>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let streams = Arc::new(Mutex::new(Vec::<WireTapStream>::new()));
    tokio::spawn({
        let streams = Arc::clone(&streams);
        async move {
            while let Ok((client, _)) = listener.accept().await {
                let streams = Arc::clone(&streams);
                tokio::spawn(async move {
                    let Ok(server_stream) = TcpStream::connect(server).await else {
                        return;
                    };
                    let index = {
                        let mut locked = streams.lock().unwrap();
                        locked.push(WireTapStream::default());
                        locked.len() - 1
                    };
                    let (mut crd, mut cwr) = tokio::io::split(client);
                    let (mut srd, mut swr) = tokio::io::split(server_stream);
                    let downstream = tokio::spawn({
                        let streams = Arc::clone(&streams);
                        async move {
                            let mut buf = [0u8; 4096];
                            loop {
                                match srd.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        {
                                            let mut locked = streams.lock().unwrap();
                                            append_tap_bytes(
                                                &mut locked[index].server_to_client,
                                                &buf[..n],
                                            );
                                        }
                                        if cwr.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });
                    let mut buf = [0u8; 4096];
                    loop {
                        match crd.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                {
                                    let mut locked = streams.lock().unwrap();
                                    append_tap_bytes(
                                        &mut locked[index].client_to_server,
                                        &buf[..n],
                                    );
                                }
                                if swr.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    downstream.abort();
                });
            }
        }
    });
    (addr, streams)
}

fn first_tls_record(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() >= 5, "wire tap captured no TLS record header");
    let len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    assert!(
        bytes.len() >= 5 + len,
        "wire tap captured a truncated first TLS record"
    );
    bytes[..5 + len].to_vec()
}

fn handshake_len(record: &[u8]) -> usize {
    (usize::from(record[6]) << 16) | (usize::from(record[7]) << 8) | usize::from(record[8])
}

fn first_client_hello_record(bytes: &[u8]) -> Vec<u8> {
    let record = first_tls_record(bytes);
    assert!(
        record.len() >= 9,
        "ClientHello record lacks a handshake header"
    );
    assert_eq!(record[0], 0x16, "client prefix is not a handshake record");
    assert_eq!(
        record[5], 0x01,
        "client prefix does not begin with ClientHello"
    );
    assert_eq!(
        record.len(),
        5 + 4 + handshake_len(&record),
        "the uploaded client prefix must be exactly one record carrying one complete logical ClientHello"
    );
    record
}

fn hello_session_id(hello_record: &[u8]) -> &[u8] {
    assert!(
        hello_record.len() >= 44,
        "hello record ends inside the session id"
    );
    let sid_len = usize::from(hello_record[43]);
    assert!(sid_len <= 32, "TLS session id length exceeds 32");
    assert!(
        hello_record.len() >= 44 + sid_len,
        "hello record ends inside the session id bytes"
    );
    &hello_record[44..44 + sid_len]
}

fn target_flight_envelope(target_flight: &[u8]) -> (Vec<u8>, Vec<[u8; 5]>) {
    assert!(
        target_flight.windows(32).any(|window| window == [0x66; 32]),
        "fixture target flight does not contain its unpatched random positive control"
    );
    let fixture_share = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([9u8; 32]));
    assert!(
        target_flight
            .windows(32)
            .any(|window| window == fixture_share.as_bytes()),
        "fixture target flight does not contain its unpatched key-share positive control"
    );

    let sh = first_tls_record(target_flight);
    let mut pos = sh.len();
    assert!(
        target_flight.len() >= pos + 6,
        "target flight ends before its CCS"
    );
    let ccs = target_flight[pos..pos + 6].to_vec();
    assert_eq!(
        ccs,
        [0x14, 0x03, 0x03, 0x00, 0x01, 0x01],
        "fixture target CCS shape"
    );
    pos += 6;
    let mut heads = Vec::new();
    while pos < target_flight.len() {
        assert!(
            target_flight.len() >= pos + 5,
            "target flight ends inside a record header"
        );
        let head: [u8; 5] = target_flight[pos..pos + 5].try_into().unwrap();
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        pos += 5;
        assert!(
            target_flight.len() >= pos + len,
            "target flight ends inside a record body"
        );
        pos += len;
        heads.push(head);
    }
    assert!(
        !heads.is_empty(),
        "target flight carries no encrypted records"
    );
    (ccs, heads)
}

fn assert_mirrored_downstream_flight(download: &[u8], client_hello: &[u8], target_flight: &[u8]) {
    let (target_ccs, target_record_heads) = target_flight_envelope(target_flight);
    let sh = first_tls_record(download);
    assert!(sh.len() >= 9, "ServerHello record lacks a handshake header");
    assert_eq!(sh[0], 0x16, "downstream prefix is not a handshake record");
    assert_eq!(
        sh[5], 0x02,
        "downstream prefix does not begin with ServerHello"
    );
    assert_eq!(
        sh.len(),
        5 + 4 + handshake_len(&sh),
        "the downstream ServerHello record must carry one complete logical ServerHello"
    );
    assert_eq!(&sh[9..11], &[0x03, 0x03], "ServerHello legacy version");
    assert_ne!(
        &sh[11..43],
        &[0x66; 32],
        "the fixture target ServerHello random reached the client unpatched"
    );

    let mut pos = 43;
    let sid_len = usize::from(sh[pos]);
    pos += 1 + sid_len;
    assert_eq!(
        &sh[44..44 + sid_len],
        hello_session_id(client_hello),
        "mirrored ServerHello must echo the client session id"
    );
    assert_eq!(
        &sh[pos..pos + 2],
        &0x1301u16.to_be_bytes(),
        "fixture cipher"
    );
    pos += 2;
    assert_eq!(sh[pos], 0, "fixture compression");
    pos += 1;
    let extensions_len = usize::from(u16::from_be_bytes([sh[pos], sh[pos + 1]]));
    pos += 2;
    let extensions_end = pos + extensions_len;
    assert_eq!(extensions_end, sh.len(), "ServerHello extension length");
    let mut saw_supported_versions = false;
    let mut server_share = None;
    while pos < extensions_end {
        let kind = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
        let len = usize::from(u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]));
        pos += 4;
        let end = pos + len;
        assert!(end <= extensions_end, "ServerHello extension overruns");
        match kind {
            0x002b => {
                assert_eq!(&sh[pos..end], &[0x03, 0x04], "TLS 1.3 selected version");
                saw_supported_versions = true;
            }
            0x0033 => {
                assert_eq!(&sh[pos..pos + 2], &0x001du16.to_be_bytes(), "fixture group");
                let share_len = usize::from(u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]));
                assert_eq!(share_len, 32, "fixture x25519 share length");
                assert_eq!(pos + 4 + share_len, end, "key_share extension shape");
                server_share = Some(sh[pos + 4..end].to_vec());
            }
            other => panic!("unexpected fixture ServerHello extension 0x{other:04x}"),
        }
        pos = end;
    }
    assert!(saw_supported_versions, "missing supported_versions");
    let server_share = server_share.expect("missing key_share");
    let fixture_share = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([9u8; 32]));
    assert_ne!(
        server_share.as_slice(),
        fixture_share.as_bytes(),
        "the fixture target key share reached the client unpatched"
    );

    let mut pos = sh.len();
    assert!(
        download.len() >= pos + 6,
        "downstream capture ended before the mirrored CCS"
    );
    assert_eq!(
        &download[pos..pos + 6],
        target_ccs.as_slice(),
        "mirrored CCS must match the same probe's target flight byte-for-byte"
    );
    pos += 6;
    for target_head in target_record_heads {
        assert!(
            download.len() >= pos + 5,
            "downstream capture ended inside the mirrored flight header"
        );
        assert_eq!(
            &download[pos..pos + 5],
            target_head,
            "mirrored encrypted record header must match the same probe's target flight"
        );
        let len = usize::from(u16::from_be_bytes([target_head[3], target_head[4]]));
        assert!(
            download.len() >= pos + 5 + len,
            "downstream capture ended inside a mirrored encrypted record"
        );
        pos += 5 + len;
    }
    assert!(
        download.len() > pos,
        "wire tap stopped at the handshake flight and cannot account for the authenticated echo"
    );
}

async fn wait_count(counter: &AtomicUsize, expected: usize, what: &str) {
    timeout(Duration::from_secs(3), async {
        while counter.load(Ordering::SeqCst) < expected {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

async fn wait_target_closes(state: &Arc<Mutex<MimicTargetState>>, expected: usize) {
    timeout(Duration::from_secs(3), async {
        while state.lock().unwrap().target_closes < expected {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {expected} target connection closes"));
}

async fn run_dial_first_case(mimic_block: &str) {
    let (target, early_dials, target_state) = start_counting_mimic_target().await;
    let echo = start_tcp_echo().await;
    let dir = tempfile::tempdir().unwrap();
    let listener_port = free_port();
    let api_port = free_port();
    let config = dir.path().join("config.yaml");
    std::fs::write(
        &config,
        runtime_yaml(listener_port, api_port, target, mimic_block),
    )
    .unwrap();
    let mut child = spawn_meow(&config, dir.path());
    wait_api(api_port, &mut child).await;

    let server = SocketAddr::from(([127, 0, 0, 1], listener_port));
    let (tap, client_streams) = start_wire_tap(server).await;

    // Bare TCP, with zero ClientHello bytes read by the listener, must
    // already occupy the early dial. This is stronger than inferring the
    // mode from a deserialized field.
    let bare = TcpStream::connect(tap).await.expect("bare tap connect");
    wait_count(&early_dials, 1, "bare-connection early dial").await;
    drop(bare);
    wait_target_closes(&target_state, 1).await;
    assert_eq!(
        target_state.lock().unwrap().preflight_parses,
        0,
        "the silent connection must not manufacture a ClientHello parse"
    );

    let adapter = vision_reality_adapter(tap.port());
    adapter_echo(&adapter, echo, b"t6 dial-first vision echo").await;

    wait_count(&early_dials, 2, "authenticated-connection early dial").await;
    wait_target_closes(&target_state, 2).await;
    let (uploads, target_flights, accepts, parses, closes) = {
        let locked = target_state.lock().unwrap();
        (
            locked.uploaded_ch_records.clone(),
            locked.server_flights.clone(),
            locked.tcp_accepts,
            locked.preflight_parses,
            locked.target_closes,
        )
    };
    assert_eq!(
        closes, 2,
        "both target connections reached their close barrier"
    );
    assert_eq!(accepts, 2, "exactly the bare and authenticated dials");
    assert_eq!(parses, 1, "exactly one ClientHello preflight parse");
    assert_eq!(uploads.len(), 1, "the original prefix must upload once");
    assert_eq!(
        target_flights.len(),
        1,
        "the mimic target must emit exactly one server flight"
    );
    let (client_first, downstream) = {
        let locked = client_streams.lock().unwrap();
        let ch_stream = locked
            .iter()
            .find(|stream| stream.client_to_server.len() >= 5 && stream.client_to_server[0] == 0x16)
            .expect("client wire tap captured no ClientHello");
        (
            first_client_hello_record(&ch_stream.client_to_server),
            ch_stream.server_to_client.clone(),
        )
    };
    assert_eq!(
        uploads[0], client_first,
        "mirror target did not receive the client's original prefix byte-for-byte"
    );
    assert_mirrored_downstream_flight(&downstream, &client_first, &target_flights[0]);
    let _ = child.kill().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t6a_absent_mimic_defaults_to_real_dial_first_runtime() {
    run_dial_first_case("").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t6a_empty_mimic_defaults_to_real_dial_first_runtime() {
    run_dial_first_case("      mimic: {}\n").await;
}

async fn start_counting_sink() -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let preflight_parses = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let accepts = Arc::clone(&accepts);
        let bytes = Arc::clone(&bytes);
        let preflight_parses = Arc::clone(&preflight_parses);
        async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                accepts.fetch_add(1, Ordering::SeqCst);
                tokio::spawn({
                    let bytes = Arc::clone(&bytes);
                    let preflight_parses = Arc::clone(&preflight_parses);
                    async move {
                        let mut buf = [0u8; 1024];
                        let mut first_record = Vec::new();
                        let mut counted = false;
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    bytes.fetch_add(n, Ordering::SeqCst);
                                    if !counted {
                                        first_record.extend_from_slice(&buf[..n]);
                                        if first_record.len() >= 5 {
                                            let len = usize::from(u16::from_be_bytes([
                                                first_record[3],
                                                first_record[4],
                                            ]));
                                            if first_record.len() >= 5 + len {
                                                counted = true;
                                                if first_record[0] == 0x16
                                                    && first_record[1] == 3
                                                    && len >= 4
                                                    && first_record[5] == 1
                                                {
                                                    preflight_parses.fetch_add(1, Ordering::SeqCst);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
    });
    (addr, accepts, bytes, preflight_parses)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t6b_mode_off_keeps_v1_auth_independent_and_cover_dialing_ordinary() {
    // First the deliberately unreachable target: authenticated service is
    // not a covert-channel health check and must not depend on cover reachability.
    let unreachable = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let echo = start_tcp_echo().await;
    let dir = tempfile::tempdir().unwrap();
    let listener_port = free_port();
    let api_port = free_port();
    let config = dir.path().join("config.yaml");
    std::fs::write(
        &config,
        runtime_yaml(
            listener_port,
            api_port,
            unreachable,
            "      mimic:\n        mode: off\n",
        ),
    )
    .unwrap();
    let mut child = spawn_meow(&config, dir.path());
    wait_api(api_port, &mut child).await;
    let adapter = vision_reality_adapter(listener_port);
    adapter_echo(&adapter, echo, b"t6 off-mode v1 authenticated echo").await;
    let _ = child.kill().await;

    // Then a counted cover target proves the zero/ordinary split in the
    // same v1 selection: authentication performs no cover TCP connect or
    // prefix parse, while an unauthenticated TLS-shaped probe still uses
    // the ordinary cover branch.
    let (target, accepts, bytes, preflight_parses) = start_counting_sink().await;
    let dir2 = tempfile::tempdir().unwrap();
    let listener_port2 = free_port();
    let api_port2 = free_port();
    let config2 = dir2.path().join("config.yaml");
    std::fs::write(
        &config2,
        runtime_yaml(
            listener_port2,
            api_port2,
            target,
            "      mimic:\n        mode: off\n",
        ),
    )
    .unwrap();
    let mut child2 = spawn_meow(&config2, dir2.path());
    wait_api(api_port2, &mut child2).await;
    let adapter = vision_reality_adapter(listener_port2);
    adapter_echo(&adapter, echo, b"t6 off-mode counted-target echo").await;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "auth must not early-dial"
    );
    assert_eq!(
        bytes.load(Ordering::SeqCst),
        0,
        "auth must not upload a prefix"
    );
    assert_eq!(
        preflight_parses.load(Ordering::SeqCst),
        0,
        "auth must not reach target-side ClientHello preflight parsing"
    );

    let mut probe = TcpStream::connect(("127.0.0.1", listener_port2))
        .await
        .expect("cover probe connect");
    probe
        .write_all(b"\x16\x03\x01\x00\x04\x01\x00\x00\x00not-a-real-client-hello")
        .await
        .expect("cover probe write");
    wait_count(&accepts, 1, "ordinary cover dial").await;
    timeout(Duration::from_secs(3), async {
        while bytes.load(Ordering::SeqCst) == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ordinary cover bytes");
    wait_count(&preflight_parses, 1, "ordinary-cover ClientHello parse").await;
    assert_eq!(
        preflight_parses.load(Ordering::SeqCst),
        1,
        "ordinary cover is the positive control for exactly one target-side preflight parse"
    );
    drop(probe);
    let _ = child2.kill().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_mimic_config_test_produces_no_cover_target_tcp_accept() {
    let (target, accepts, _bytes, _preflight_parses) = start_counting_sink().await;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    std::fs::write(
        &config,
        runtime_yaml(free_port(), free_port(), target, "      mimic: {}\n"),
    )
    .unwrap();

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"));
    command
        .arg("-f")
        .arg(&config)
        .arg("-d")
        .arg(dir.path())
        .arg("-t")
        .current_dir(dir.path());
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(variable);
    }
    let output = timeout(T, command.output())
        .await
        .expect("-t must not hang")
        .expect("run meow -t");
    assert!(
        output.status.success(),
        "valid mimic config must pass -t: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    sleep(Duration::from_millis(100)).await;
    // The sink can witness only the absence of a TCP accept. It cannot
    // distinguish every resolver or health-check implementation detail that
    // stops before a connect reaches this dest.
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "-t produced no cover-target TCP accept"
    );

    let bad = dir.path().join("bad.yaml");
    std::fs::write(
        &bad,
        runtime_yaml(
            free_port(),
            free_port(),
            target,
            "      mimic:\n        probe-timeout-ms: 15001\n",
        ),
    )
    .unwrap();
    let mut bad_command = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"));
    bad_command
        .arg("-f")
        .arg(&bad)
        .arg("-d")
        .arg(dir.path())
        .arg("-t")
        .current_dir(dir.path());
    let output = bad_command.output().await.expect("run bad meow -t");
    assert!(!output.status.success(), "invalid mimic must fail -t");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("mimic")
            || String::from_utf8_lossy(&output.stdout).contains("mimic"),
        "the -t rejection must name mimic: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}
