//! Chain verdicts on `dialer-proxy` front hops through automatic groups
//! (see `meow_common::chain_health`).

use super::test_support::{DuplexConn, MockProxy, REPLY};
use super::urltest::UrlTestGroup;
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn target() -> ChainTarget {
    ChainTarget::from_server_addr("snell.example.com:8443").unwrap()
}

/// A watched front hop to [`target`] whose server end the test drives.
fn watched(
    health: &Arc<ChainHealth>,
    member: &Arc<dyn Proxy>,
) -> (Box<dyn ProxyConn>, DuplexStream) {
    let (client, server) = tokio::io::duplex(1024);
    let conn = watch_front_hop(
        Box::new(DuplexConn(client)),
        "fast",
        health,
        target(),
        member,
    );
    (conn, server)
}

/// A chain the front closes once it has seen the chained header.
async fn closed_after_the_header(health: &Arc<ChainHealth>, member: &Arc<dyn Proxy>) {
    let (mut conn, mut server) = watched(health, member);
    conn.write_all(b"header").await.unwrap();
    let mut buf = [0u8; 16];
    assert!(server.read(&mut buf).await.unwrap() > 0);
    drop(server);
    assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
}

/// A chain the far end answers.
async fn answered(health: &Arc<ChainHealth>, member: &Arc<dyn Proxy>) {
    let (mut conn, mut server) = watched(health, member);
    conn.write_all(b"header").await.unwrap();
    let mut buf = [0u8; 64];
    assert!(server.read(&mut buf).await.unwrap() > 0);
    server.write_all(REPLY).await.unwrap();
    assert_eq!(conn.read(&mut buf).await.unwrap(), REPLY.len());
    // Whatever happens after the first byte says nothing more.
    drop(server);
    assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn two_chains_closed_before_a_reply_block_the_member() {
    let health = Arc::new(ChainHealth::new());
    let member: Arc<dyn Proxy> = MockProxy::new("SG-01");
    closed_after_the_header(&health, &member).await;
    assert!(
        !health.is_blocked(&target(), "SG-01"),
        "one strike is no block"
    );
    closed_after_the_header(&health, &member).await;
    assert!(health.is_blocked(&target(), "SG-01"));
    assert!(
        !health.is_blocked(
            &ChainTarget::from_server_addr("other.example.com:8443").unwrap(),
            "SG-01"
        ),
        "the block holds for that target only"
    );
}

#[tokio::test]
async fn an_answered_chain_clears_the_strikes() {
    let health = Arc::new(ChainHealth::new());
    let member: Arc<dyn Proxy> = MockProxy::new("SG-01");
    closed_after_the_header(&health, &member).await;
    answered(&health, &member).await;
    answered(&health, &member).await;
    closed_after_the_header(&health, &member).await;
    assert!(!health.is_blocked(&target(), "SG-01"));
}

#[tokio::test]
async fn eof_before_a_write_or_after_our_shutdown_says_nothing() {
    let health = Arc::new(ChainHealth::new());
    let member: Arc<dyn Proxy> = MockProxy::new("SG-01");
    let mut buf = [0u8; 16];
    for _ in 0..3 {
        let (mut conn, server) = watched(&health, &member);
        drop(server);
        assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
    }
    for _ in 0..3 {
        let (mut conn, mut server) = watched(&health, &member);
        conn.write_all(b"header").await.unwrap();
        conn.shutdown().await.unwrap();
        assert!(server.read(&mut buf).await.unwrap() > 0);
        drop(server);
        assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
    }
    assert!(!health.is_blocked(&target(), "SG-01"));
}

#[tokio::test]
async fn a_write_error_before_a_reply_counts_against_the_member() {
    let health = Arc::new(ChainHealth::new());
    let member: Arc<dyn Proxy> = MockProxy::new("SG-01");
    for _ in 0..2 {
        let (mut conn, server) = watched(&health, &member);
        drop(server);
        assert!(conn.write_all(b"header").await.is_err());
    }
    assert!(health.is_blocked(&target(), "SG-01"));
}

/// An automatic group as a member judges its own pick; the outer group
/// leaves the stream alone.
#[tokio::test]
async fn a_member_group_keeps_its_own_verdicts() {
    let health = Arc::new(ChainHealth::new());
    let inner: Arc<dyn Proxy> = Arc::new(UrlTestGroup::new(
        "inner",
        vec![MockProxy::new("SG-01") as Arc<dyn Proxy>],
        0,
    ));
    closed_after_the_header(&health, &inner).await;
    closed_after_the_header(&health, &inner).await;
    assert!(!health.is_blocked(&target(), "inner"));
}

#[test]
fn a_blocked_pick_gives_way_to_the_next_usable_member() {
    let health = ChainHealth::new();
    let t = target();
    let block = |name: &str| {
        health.record_failed(
            &t,
            name,
            ChainVerdict::Probe {
                hold: Duration::from_secs(600),
            },
        );
    };
    let [a, b, c]: [Arc<dyn Proxy>; 3] = ["a", "b", "c"].map(|n| MockProxy::new(n) as _);
    let dead: Arc<dyn Proxy> = {
        let dead = MockProxy::new("dead");
        dead.set_alive(false);
        dead
    };
    let members = || {
        vec![
            Arc::clone(&a),
            Arc::clone(&dead),
            Arc::clone(&b),
            Arc::clone(&c),
        ]
    };
    let pick = |pick: &Arc<dyn Proxy>| {
        front_hop_pick(
            "fast",
            &health,
            &t,
            Arc::clone(pick),
            members,
            |p| p.alive(),
            true,
        )
        .name()
        .to_owned()
    };

    assert_eq!(pick(&a), "a", "an unblocked pick stands");
    block("a");
    assert_eq!(pick(&a), "b", "the next live, unblocked member");
    assert_eq!(pick(&c), "c");
    block("b");
    assert_eq!(pick(&a), "c");
    block("c");
    assert_eq!(
        pick(&a),
        "a",
        "with every live member blocked the group's own pick stands"
    );
}
