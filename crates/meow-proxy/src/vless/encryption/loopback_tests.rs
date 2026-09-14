//! Loopback integration tests: the real client handshake against the reference
//! server port over an in-memory duplex. Because both are faithful ports of
//! Xray/mihomo's own `client.go` / `server.go`, a successful bidirectional
//! exchange proves the client's record framing, nonce schedule, BLAKE3
//! contexts, XOR-header masking, and 0-RTT resumption are wire-correct.

use std::sync::Arc;

use base64::Engine;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use super::client::ClientInstance;
use super::factory::parse_client_encryption;
use super::server::{ServerInstance, ServerKey};

/// Which long-term key type(s) to use for the NFS layer.
enum KeySpec {
    X25519,
    MlKem,
    /// A multi-key relay chain (exercises the `lastCTR`/hash32 path).
    Chain,
}

fn make_keys(spec: &KeySpec) -> Vec<ServerKey> {
    match spec {
        KeySpec::X25519 => vec![ServerKey::new_x25519()],
        KeySpec::MlKem => vec![ServerKey::new_mlkem()],
        KeySpec::Chain => vec![ServerKey::new_x25519(), ServerKey::new_mlkem()],
    }
}

fn client_encryption_string(mode: &str, rtt: &str, keys: &[ServerKey]) -> String {
    let mut parts = vec![
        "mlkem768x25519plus".to_string(),
        mode.to_string(),
        rtt.to_string(),
    ];
    for k in keys {
        parts.push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k.public_bytes()));
    }
    parts.join(".")
}

fn xor_mode_of(mode: &str) -> u32 {
    match mode {
        "native" => 0,
        "xorpub" => 1,
        "random" => 2,
        _ => unreachable!(),
    }
}

/// Drive one client→server handshake pair and a full bidirectional exchange.
///
/// The server handshake runs on its own task: in the 0-RTT fast path the client
/// handshake returns *before* sending anything (the clientHello piggybacks on
/// the first data write), so the server can only complete once that first write
/// lands. Awaiting the server task after the initial client write covers both
/// the 1-RTT and 0-RTT timelines.
async fn connect_and_exchange(client: &ClientInstance, server: Arc<ServerInstance>) {
    let (c_raw, s_raw) = duplex(256 * 1024);
    let server_task =
        tokio::spawn(async move { server.handshake(Box::new(s_raw)).await.expect("server") });

    let mut c = client.handshake(Box::new(c_raw)).await.expect("client");

    // First client→server write — this is what flushes a 0-RTT clientHello.
    c.write_all(b"ping from the client").await.unwrap();
    c.flush().await.unwrap();

    let mut s = server_task.await.expect("server task");
    let mut buf = [0u8; 20];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping from the client");

    // server → client
    s.write_all(b"pong back from server").await.unwrap();
    s.flush().await.unwrap();
    let mut buf2 = [0u8; 21];
    c.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"pong back from server");

    // large, multi-record payload client → server
    let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    c.write_all(&big).await.unwrap();
    c.flush().await.unwrap();
    let mut got = vec![0u8; big.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(got, big, "large payload must round-trip intact");
}

async fn run_case(mode: &str, keys_spec: KeySpec) {
    let keys = make_keys(&keys_spec);
    let enc = client_encryption_string(mode, "1rtt", &keys);
    let client = parse_client_encryption(&enc).unwrap().unwrap();
    let server = Arc::new(ServerInstance::init(keys, xor_mode_of(mode), 0, 0, "").unwrap());

    connect_and_exchange(&client, server).await;
}

#[tokio::test]
async fn native_x25519_1rtt() {
    run_case("native", KeySpec::X25519).await;
}

/// Same handshake over a real socket: `TcpStream` already implements `Stream`
/// via the blanket impl, and a real NIC path adds buffering/segmentation the
/// in-memory duplex never produces.
#[tokio::test]
async fn native_x25519_1rtt_over_tcp() {
    let keys = make_keys(&KeySpec::X25519);
    let enc = client_encryption_string("native", "1rtt", &keys);
    let client = parse_client_encryption(&enc).unwrap().unwrap();
    let server = Arc::new(ServerInstance::init(keys, 0, 0, 0, "").unwrap());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (raw, _) = listener.accept().await.unwrap();
        server.handshake(Box::new(raw)).await.expect("server")
    });
    let c_raw = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut c = client.handshake(Box::new(c_raw)).await.expect("client");

    c.write_all(b"ping over real tcp").await.unwrap();
    c.flush().await.unwrap();
    let mut s = server_task.await.expect("server task");
    let mut buf = [0u8; 18];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping over real tcp");
    s.write_all(b"pong back").await.unwrap();
    s.flush().await.unwrap();
    let mut buf2 = [0u8; 9];
    c.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"pong back");
}

#[tokio::test]
async fn native_mlkem_1rtt() {
    run_case("native", KeySpec::MlKem).await;
}

#[tokio::test]
async fn xorpub_x25519_1rtt() {
    run_case("xorpub", KeySpec::X25519).await;
}

#[tokio::test]
async fn xorpub_mlkem_1rtt() {
    run_case("xorpub", KeySpec::MlKem).await;
}

#[tokio::test]
async fn random_x25519_1rtt() {
    run_case("random", KeySpec::X25519).await;
}

#[tokio::test]
async fn random_mlkem_1rtt() {
    run_case("random", KeySpec::MlKem).await;
}

#[tokio::test]
async fn native_relay_chain_1rtt() {
    run_case("native", KeySpec::Chain).await;
}

#[tokio::test]
async fn random_relay_chain_1rtt() {
    run_case("random", KeySpec::Chain).await;
}

/// 0-RTT resumption: a first 1-RTT handshake seeds the client ticket cache and
/// the server session table; a second dial replays the ticket and skips the
/// round trip. Verified for both `native` and `random` XOR modes.
async fn run_0rtt_case(mode: &str) {
    let keys = make_keys(&KeySpec::X25519);
    let enc = client_encryption_string(mode, "0rtt", &keys);
    let client = parse_client_encryption(&enc).unwrap().unwrap();
    // seconds_from > 0 ⇒ the server hands out a non-expiring resumption ticket.
    let server = Arc::new(ServerInstance::init(keys, xor_mode_of(mode), 600, 0, "").unwrap());

    // First dial: full 1-RTT, seeds the client cache and server session table.
    connect_and_exchange(&client, Arc::clone(&server)).await;

    // Second dial: should take the 0-RTT fast path.
    connect_and_exchange(&client, server).await;
}

#[tokio::test]
async fn native_x25519_0rtt_resumption() {
    run_0rtt_case("native").await;
}

#[tokio::test]
async fn random_x25519_0rtt_resumption() {
    run_0rtt_case("random").await;
}

/// Half-close regression (issue #514 review follow-up): a server-side FIN
/// on the send direction ends the client's record read loop on a clean
/// boundary EOF — but the exchange is only half-closed, so a client still
/// uploading must keep reaching the server. The old supervisor aborted the
/// write task with the read loop, silently dropping the tail of uploads.
#[tokio::test]
async fn server_half_close_keeps_client_upload_alive() {
    let keys = make_keys(&KeySpec::X25519);
    let enc = client_encryption_string("native", "1rtt", &keys);
    let client = parse_client_encryption(&enc).unwrap().unwrap();
    let server = Arc::new(ServerInstance::init(keys, 0, 0, 0, "").unwrap());

    let (c_raw, s_raw) = duplex(256 * 1024);
    let server_task =
        tokio::spawn(async move { server.handshake(Box::new(s_raw)).await.expect("server") });
    let mut c = client.handshake(Box::new(c_raw)).await.expect("client");

    c.write_all(b"ping").await.unwrap();
    c.flush().await.unwrap();
    let mut s = server_task.await.expect("server task");
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // Server half-closes its send direction but keeps reading uploads.
    s.shutdown().await.unwrap();

    // The client observes the half-close on its read direction.
    let mut sink = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(2), c.read_to_end(&mut sink))
        .await
        .expect("client read side must observe the server FIN")
        .unwrap();

    // Give the supervisor a scheduling slice: under the buggy version it
    // aborts the write task as soon as the read loop ends.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // A post-FIN upload must still reach the server.
    c.write_all(b"post-fin upload").await.unwrap();
    c.flush().await.unwrap();
    let mut got = [0u8; 15];
    tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut got))
        .await
        .expect("server must keep receiving uploads after its own FIN")
        .unwrap();
    assert_eq!(&got, b"post-fin upload");
}
