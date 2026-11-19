//! `lan-allowed-ips`/`lan-disallowed-ips` — the shared inbound ACL gate
//! in `MixedListener`'s accept loop.
//!
//! The check runs after `accept` and before keepalive/protocol dispatch,
//! so a denied peer must see a silently dropped socket: connect succeeds
//! (the kernel already completed the handshake) and the next read hits
//! EOF with zero protocol bytes — no SOCKS reply, no HTTP response.

#![cfg(feature = "listener-mixed")]

mod common;

use common::direct_tunnel;
use meow_common::{AuthConfig, Credentials, LanAcl};
use meow_listener::MixedListener;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn acl(allowed: &[&str], denied: &[&str]) -> Arc<LanAcl> {
    Arc::new(LanAcl::new(
        allowed.iter().map(|s| s.parse().unwrap()).collect(),
        denied.iter().map(|s| s.parse().unwrap()).collect(),
    ))
}

/// Start a `MixedListener` on a fresh ephemeral port with the given ACL
/// (and optional auth store) and return the bound address.
async fn start_acl_listener(acl: Arc<LanAcl>, auth: Option<AuthConfig>) -> std::net::SocketAddr {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = socket.local_addr().unwrap();
    let mut listener =
        MixedListener::new(direct_tunnel(), bound, "acl-test".to_string()).with_lan_acl(acl);
    if let Some(auth) = auth {
        listener = listener.with_auth(Arc::new(auth));
    }
    tokio::spawn(async move {
        let _ = listener.run_on(socket).await;
    });
    bound
}

/// A denied connection is dropped before protocol handling: the peer
/// reads EOF or a reset — the dropped socket RSTs when bytes were in
/// flight — but never a SOCKS or HTTP response byte.
async fn assert_dropped(bound: std::net::SocketAddr) {
    let mut stream = TcpStream::connect(bound).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 8];
    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("denied peer got {n} bytes of protocol response"),
        Err(_) => panic!("denied connection must close promptly, not hang"),
    }
}

/// An admitted connection reaches the SOCKS5 handler, which answers the
/// greeting with method-selection bytes.
async fn assert_socks_admitted(bound: std::net::SocketAddr) {
    let mut stream = TcpStream::connect(bound).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf))
        .await
        .expect("admitted connection must answer")
        .expect("read");
    assert_eq!(buf, [0x05, 0x00], "expected SOCKS5 no-auth method reply");
}

#[tokio::test]
async fn denied_peer_drops_without_response() {
    let bound = start_acl_listener(acl(&["0.0.0.0/0"], &["127.0.0.0/8"]), None).await;
    assert_dropped(bound).await;
}

#[tokio::test]
async fn admitted_peer_reaches_socks_handler() {
    let bound = start_acl_listener(acl(&["127.0.0.0/8"], &[]), None).await;
    assert_socks_admitted(bound).await;
}

#[tokio::test]
async fn empty_allow_list_drops_everything() {
    let bound = start_acl_listener(acl(&[], &[]), None).await;
    assert_dropped(bound).await;
}

#[tokio::test]
async fn acl_runs_with_empty_credential_store() {
    // `with_auth` discards an empty store — the ACL must still gate.
    let auth = AuthConfig::new(Arc::new(Credentials::new(HashMap::new())), vec![]);
    let bound = start_acl_listener(acl(&[], &[]), Some(auth)).await;
    assert_dropped(bound).await;
}

#[tokio::test]
async fn acl_runs_before_skip_auth_prefixes() {
    // A peer inside `skip-auth-prefixes` is exempt from auth, never from
    // the ACL — the filter is strictly earlier in the accept loop.
    let auth = AuthConfig::new(
        Arc::new(Credentials::new(
            [("u".to_string(), "p".to_string())].into_iter().collect(),
        )),
        vec!["127.0.0.0/8".parse().unwrap()],
    );
    let bound = start_acl_listener(acl(&[], &[]), Some(auth)).await;
    assert_dropped(bound).await;
}
