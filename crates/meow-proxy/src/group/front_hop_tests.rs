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
            "timed out",
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
            None,
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

/// `风之谷`, a fallback over `daniel`, which dials its server through
/// `fast`, and a spare.
struct Wind {
    wind: Arc<dyn Proxy>,
    daniel: Arc<dyn Proxy>,
    fast: Arc<dyn Proxy>,
    /// Resolves `fast` for `daniel`'s dials.
    _registry: crate::dialer::ProxyRegistry,
}

/// [`Wind`] with `fast` a url-test over `members`.
fn wind_over(members: Vec<Arc<dyn Proxy>>) -> Wind {
    use super::fallback::FallbackGroup;
    use super::test_support::{registry_of, ChainedProxy};
    let fast: Arc<dyn Proxy> = Arc::new(UrlTestGroup::new("fast", members, 0));
    let registry = registry_of(&[&fast]);
    let daniel: Arc<dyn Proxy> =
        ChainedProxy::handshaking("daniel", "snell.example.com:8443", "fast", &registry);
    daniel.health().record_delay(30);
    let spare = MockProxy::new("daniel-eu");
    spare.set_delay(40);
    let wind: Arc<dyn Proxy> = Arc::new(FallbackGroup::new(
        "风之谷",
        vec![Arc::clone(&daniel), spare as Arc<dyn Proxy>],
    ));
    Wind {
        wind,
        daniel,
        fast,
        _registry: registry,
    }
}

/// A front member refusing the connection is `fast`'s failure: `fast`
/// marks its member dead, and `风之谷` keeps `daniel`, whose next dial
/// goes through the next member.
#[tokio::test]
async fn a_refusing_front_member_does_not_take_the_chained_outbound_down() {
    use super::test_support::StreamProxy;
    let refusing = MockProxy::new_failing("SG-01", AdapterType::Vless, "connection refused");
    refusing.set_delay(10);
    let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
    clean.set_delay(20);
    let w = wind_over(vec![
        Arc::clone(&refusing) as Arc<dyn Proxy>,
        Arc::clone(&clean) as Arc<dyn Proxy>,
    ]);

    let metadata = Metadata::default();
    assert!(w.wind.dial_tcp(&metadata).await.is_err());
    assert!(
        !refusing.alive(),
        "fast counts the refusal against its member"
    );
    assert!(w.daniel.alive(), "风之谷 does not count it against daniel");
    assert!(w.wind.dial_tcp(&metadata).await.is_ok());
    assert_eq!(clean.dials(), 1);
}

/// With no live member left in its front group, the chained outbound has
/// no way out: the refusal counts against it.
#[tokio::test]
async fn a_front_group_with_no_live_member_left_counts_against_the_outbound() {
    let refusing = MockProxy::new_failing("SG-01", AdapterType::Vless, "connection refused");
    refusing.set_delay(10);
    let w = wind_over(vec![refusing as Arc<dyn Proxy>]);
    assert!(w.wind.dial_tcp(&Metadata::default()).await.is_err());
    assert!(!w.daniel.alive());
}

/// A chained outbound its group's dials take down between health checks:
/// no health check failed, so the logbook records it then, with the member
/// of the front group the dials went through, and the next passing health
/// check ends it.
#[tokio::test]
async fn a_chained_outbound_its_dials_take_down_is_in_the_logbook() {
    use super::fallback::FallbackGroup;
    use super::test_support::{registry_of, ChainedProxy, StreamProxy, TestLogbook};
    let book = TestLogbook::install();
    let refusing = MockProxy::new_failing("SG-01", AdapterType::Vless, "connection refused");
    refusing.set_delay(10);
    let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
    let clean_member: Arc<dyn Proxy> = Arc::clone(&clean) as _;
    clean_member.health().set_alive(false);
    let fast: Arc<dyn Proxy> = Arc::new(UrlTestGroup::new(
        "fast",
        vec![Arc::clone(&refusing) as Arc<dyn Proxy>, clean_member],
        0,
    ));
    let registry = registry_of(&[&fast]);
    let owner = "daniel-dials";
    let daniel: Arc<dyn Proxy> =
        ChainedProxy::new(owner, "snell.example.com:8443", "fast", &registry);
    daniel.health().record_delay(30);
    let wind: Arc<dyn Proxy> = Arc::new(FallbackGroup::new("风之谷", vec![Arc::clone(&daniel)]));

    assert!(wind.dial_tcp(&Metadata::default()).await.is_err());
    assert!(!daniel.alive());
    let entries = book.entries(owner);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(
        (entries[0].kind.as_str(), entries[0].level),
        (logbook::kind::DIALER_PROXY_CHECK, Level::Error)
    );
    assert_eq!(
        entries[0].message,
        "'daniel-dials' is down: its dials from '风之谷' failed (connection refused) through \
         'SG-01' of 'fast'"
    );
    let fields = &entries[0].fields;
    assert_eq!(
        (
            &fields["group"],
            &fields["member"],
            &fields["by"],
            &fields["reason"]
        ),
        (
            &"fast".into(),
            &"SG-01".into(),
            &"风之谷".into(),
            &"connection refused".into()
        )
    );

    // HK-01 is back, and the health check reaches the server through it.
    clean.set_delay(20);
    let swept = crate::health::sweep_members(
        vec![(owner.to_owned(), Arc::clone(&daniel))],
        std::slice::from_ref(&fast),
        "http://probe.example/generate_204",
        None,
        Duration::from_secs(5),
        1,
        Duration::from_secs(600),
    )
    .await;
    assert!(swept[0].delay > 0, "{swept:?}");
    let checks: Vec<_> = book
        .entries(owner)
        .into_iter()
        .filter(|e| e.kind == logbook::kind::DIALER_PROXY_CHECK)
        .collect();
    assert_eq!(checks.len(), 2, "{checks:?}");
    assert_eq!(
        (checks[0].level, checks[0].message.as_str()),
        (Level::Info, "'daniel-dials' passes its health check again")
    );
}

/// An outbound whose front is a single proxy, or that has none, is not a
/// chain the logbook follows: its group takes it down without an entry.
#[tokio::test]
async fn an_outbound_its_dials_take_down_without_a_front_group_is_not_recorded() {
    use super::fallback::FallbackGroup;
    use super::test_support::{registry_of, ChainedProxy, TestLogbook};
    let book = TestLogbook::install();
    let front: Arc<dyn Proxy> =
        MockProxy::new_failing("single-front", AdapterType::Vless, "connection refused");
    let registry = registry_of(&[&front]);
    let chained: Arc<dyn Proxy> = ChainedProxy::new(
        "over-single-front",
        "snell.example.com:8443",
        "single-front",
        &registry,
    );
    chained.health().record_delay(30);
    let unchained: Arc<dyn Proxy> =
        MockProxy::new_failing("unchained-dials", AdapterType::Vless, "connection refused");
    unchained.health().record_delay(30);

    for member in [chained, unchained] {
        let group: Arc<dyn Proxy> =
            Arc::new(FallbackGroup::new("风之谷", vec![Arc::clone(&member)]));
        assert!(group.dial_tcp(&Metadata::default()).await.is_err());
        assert!(!member.alive(), "{}", member.name());
        assert!(book.entries(member.name()).is_empty(), "{}", member.name());
    }
}

/// A url-test front keeps a target's chains on their carrier while the
/// fastest member to the test URL changes, and moves them once the carrier
/// is blocked for the target, which the logbook records under the chained
/// outbound.
#[tokio::test]
async fn a_url_test_front_keeps_chains_on_their_carrier() {
    use super::test_support::{registry_of, StreamProxy, TestLogbook};
    use crate::dialer::{DialerTarget, NamedProxyDialer, TcpDialer as _};
    let book = TestLogbook::install();
    let first = StreamProxy::new("SG-01", "10.0.0.1:443");
    first.set_delay(20);
    let second = StreamProxy::new("HK-01", "10.0.0.2:443");
    second.set_delay(30);
    let fast: Arc<dyn Proxy> = Arc::new(UrlTestGroup::new(
        "fast",
        vec![
            Arc::clone(&first) as Arc<dyn Proxy>,
            Arc::clone(&second) as Arc<dyn Proxy>,
        ],
        0,
    ));
    let registry = registry_of(&[&fast]);
    let owner = "carrier-daniel";
    let dialer = NamedProxyDialer::new(DialerTarget::new("fast", &registry)).owned_by(owner);
    let chain = || async {
        let mut stream = dialer.dial("snell.example.com", 8443, false).await.unwrap();
        stream.write_all(b"chained header").await.unwrap();
        let mut buf = [0u8; 128];
        stream.read(&mut buf).await.unwrap_or(0)
    };

    assert_eq!(chain().await, REPLY.len());
    let health = fast.chain_health().unwrap();
    assert_eq!(health.carrier(&target()).as_deref(), Some("SG-01"));

    // HK-01 is now the fastest; the chains stay on SG-01.
    second.set_delay(5);
    assert_eq!(chain().await, REPLY.len());
    assert_eq!((first.dials(), second.dials()), (2, 0));

    let hold = ChainVerdict::Probe {
        hold: Duration::from_secs(600),
    };
    health.record_failed(&target(), "SG-01", hold, "timed out");
    assert_eq!(chain().await, REPLY.len());
    assert_eq!((first.dials(), second.dials()), (2, 1));
    assert_eq!(health.carrier(&target()).as_deref(), Some("HK-01"));
    let entries = book.entries(owner);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(
        entries[0].message,
        "'carrier-daniel' now dials through 'HK-01' of 'fast' (was 'SG-01': timed out)"
    );

    // A dead carrier gives way too.
    health.record_reached(&target(), "SG-01");
    meow_common::ProxyAdapter::health(&*first).set_alive(false);
    assert_eq!(chain().await, REPLY.len());
    assert_eq!((first.dials(), second.dials()), (2, 2));
}

/// A burst of dials through a front member that closes the server's port
/// before any reply, a member that never carried a chain there: each fails
/// for the member, so `风之谷` keeps `daniel`, and the next dial goes
/// through the next member. The member is blocked while the rest of the
/// burst is in flight, which makes none of them a last resort: `fast` took
/// it unblocked.
#[tokio::test]
async fn a_burst_through_an_unproven_front_member_keeps_the_outbound() {
    use super::test_support::StreamProxy;
    use meow_common::chain_health::PASSIVE_STRIKES;
    let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
    audited.set_delay(10);
    let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
    clean.set_delay(20);
    let w = wind_over(vec![
        Arc::clone(&audited) as Arc<dyn Proxy>,
        Arc::clone(&clean) as Arc<dyn Proxy>,
    ]);

    // Enough that the failures after the block would take `daniel` down.
    let size = usize::from(PASSIVE_STRIKES) + DIAL_FAILURE_THRESHOLD as usize;
    let metadata = Metadata::default();
    let burst = (0..size).map(|_| w.wind.dial_tcp(&metadata));
    let failed = futures::future::join_all(burst)
        .await
        .iter()
        .filter(|r| r.is_err())
        .count();
    assert_eq!((failed, audited.dials()), (size, size));
    assert!(w.daniel.alive());
    assert!(w.wind.dial_tcp(&metadata).await.is_ok());
    assert_eq!(clean.dials(), 1);
}

/// The same burst through the member that carried the chains before counts
/// against `daniel`: a carrier failing is the likelier sign of a server
/// that is down.
#[tokio::test]
async fn a_burst_through_the_carrier_counts_against_the_outbound() {
    use super::test_support::StreamProxy;
    let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
    audited.set_delay(10);
    let w = wind_over(vec![Arc::clone(&audited) as Arc<dyn Proxy>]);
    w.fast
        .chain_health()
        .unwrap()
        .record_reached(&target(), "SG-01");

    let metadata = Metadata::default();
    let burst = (0..6).map(|_| w.wind.dial_tcp(&metadata));
    futures::future::join_all(burst).await;
    assert!(!w.daniel.alive());
}

/// While the failing member is the front group's last live one, the chained
/// outbound has no other way out: each failure counts against it, and the
/// two go down together.
#[tokio::test]
async fn a_failing_last_live_front_member_counts_against_the_outbound() {
    let failing = MockProxy::new_failing("SG-01", AdapterType::Vless, "handshake timed out");
    failing.set_delay(10);
    let dead = MockProxy::new("HK-01");
    dead.set_alive(false);
    let w = wind_over(vec![
        Arc::clone(&failing) as Arc<dyn Proxy>,
        dead as Arc<dyn Proxy>,
    ]);
    let metadata = Metadata::default();
    for _ in 0..DIAL_FAILURE_THRESHOLD {
        assert!(w.wind.dial_tcp(&metadata).await.is_err());
    }
    assert!(!failing.alive());
    assert!(!w.daniel.alive());
}

/// `风之谷`'s dial under the deadline the tunnel sets.
async fn dial_in_time(w: &Wind) -> meow_common::Result<Box<dyn ProxyConn>> {
    meow_common::with_dial_timeout(w.wind.name(), w.wind.dial_tcp(&Metadata::default())).await
}

fn timed_out(result: &meow_common::Result<Box<dyn ProxyConn>>) -> bool {
    matches!(result, Err(MeowError::Io(e)) if e.kind() == io::ErrorKind::TimedOut)
}

/// A burst of dials that expire at a front member whose dials hang: the
/// member's own dial times out first, inside `fast`, which counts it; and
/// `风之谷` keeps `daniel`, whose next dial goes through the next member.
#[tokio::test(start_paused = true)]
async fn front_dials_that_hang_past_the_deadline_keep_the_outbound() {
    use super::test_support::StreamProxy;
    let hanging = StreamProxy::hanging("SG-01", "10.0.0.1:443");
    hanging.set_delay(10);
    let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
    clean.set_delay(20);
    let w = wind_over(vec![
        Arc::clone(&hanging) as Arc<dyn Proxy>,
        Arc::clone(&clean) as Arc<dyn Proxy>,
    ]);

    let burst = (0..DIAL_FAILURE_THRESHOLD).map(|_| dial_in_time(&w));
    let results = futures::future::join_all(burst).await;
    assert!(results.iter().all(timed_out));
    assert!(!hanging.alive(), "fast counts the hung dials");
    assert!(
        w.daniel.alive(),
        "风之谷 does not count them against daniel"
    );
    assert!(dial_in_time(&w).await.is_ok());
    assert_eq!(clean.dials(), 1);
}

/// A burst through a front member that black-holes the server's port: the
/// chained handshake waits until the deadline drops it, which fails for the
/// member like EOF before a reply. `风之谷` keeps `daniel`, and `fast`, with
/// the member blocked for the server, routes the next dial around it.
#[tokio::test(start_paused = true)]
async fn a_front_member_that_black_holes_the_server_keeps_the_outbound() {
    use super::test_support::StreamProxy;
    let silent = StreamProxy::black_holing("SG-01", "10.0.0.1:443", 8443);
    silent.set_delay(10);
    let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
    clean.set_delay(20);
    let w = wind_over(vec![
        Arc::clone(&silent) as Arc<dyn Proxy>,
        Arc::clone(&clean) as Arc<dyn Proxy>,
    ]);

    let burst = (0..DIAL_FAILURE_THRESHOLD).map(|_| dial_in_time(&w));
    let results = futures::future::join_all(burst).await;
    assert!(results.iter().all(timed_out));
    assert!(w.daniel.alive());
    let health = w.fast.chain_health().unwrap();
    assert!(health.is_blocked(&target(), "SG-01"));
    assert!(dial_in_time(&w).await.is_ok());
    assert_eq!(clean.dials(), 1);
}

/// The same black hole in the member that carried the chains counts
/// against `daniel`, as a carrier's EOF does.
#[tokio::test(start_paused = true)]
async fn a_carrier_that_black_holes_the_server_counts_against_the_outbound() {
    use super::test_support::StreamProxy;
    let silent = StreamProxy::black_holing("SG-01", "10.0.0.1:443", 8443);
    silent.set_delay(10);
    let w = wind_over(vec![Arc::clone(&silent) as Arc<dyn Proxy>]);
    w.fast
        .chain_health()
        .unwrap()
        .record_reached(&target(), "SG-01");

    let burst = (0..DIAL_FAILURE_THRESHOLD).map(|_| dial_in_time(&w));
    futures::future::join_all(burst).await;
    assert!(!w.daniel.alive());
}

/// `风之谷`'s dials until it gives up on `daniel`, each one failing, at most
/// `limit`.
async fn dials_until_daniel_is_down(w: &Wind, limit: usize) -> usize {
    let mut dials = 0;
    while w.daniel.alive() {
        assert!(
            dials < limit,
            "daniel is still up after {dials} failed dials"
        );
        assert!(w.wind.dial_tcp(&Metadata::default()).await.is_err());
        dials += 1;
    }
    dials
}

/// `daniel`'s server is down and closes every chain, through any member of
/// `fast`. The first members to fail it take the blame, each blocked after
/// two strikes; the next one makes the server the likelier fault, so its
/// failures count against `daniel` and block no member, and `风之谷` gives
/// up on `daniel` however many members `fast` has.
#[tokio::test]
async fn a_server_that_closes_every_chain_takes_the_outbound_down() {
    use super::test_support::StreamProxy;
    use meow_common::chain_health::{BLAMED_MEMBERS, PASSIVE_STRIKES};
    let members: Vec<Arc<StreamProxy>> = (0..8u16)
        .map(|i| {
            let member =
                StreamProxy::auditing(&format!("M{i}"), &format!("10.0.0.{}:443", i + 1), 8443);
            member.set_delay(10 + i);
            member
        })
        .collect();
    let w = wind_over(
        members
            .iter()
            .map(|m| Arc::clone(m) as Arc<dyn Proxy>)
            .collect(),
    );

    let dials = dials_until_daniel_is_down(&w, 32).await;
    assert_eq!(
        dials,
        BLAMED_MEMBERS * usize::from(PASSIVE_STRIKES) + DIAL_FAILURE_THRESHOLD as usize
    );
    let health = w.fast.chain_health().unwrap();
    let blocked: Vec<String> = (0..members.len())
        .map(|i| format!("M{i}"))
        .filter(|name| health.is_blocked(&target(), name))
        .collect();
    assert_eq!(blocked, ["M0", "M1", "M2"]);
    let front_dials = || members.iter().map(|m| m.dials()).sum::<usize>();
    let before = front_dials();
    let _ = w.wind.dial_tcp(&Metadata::default()).await;
    assert_eq!(front_dials(), before, "风之谷 dials daniel-eu now");
}

/// The same server refusing every chain, through front members that report
/// it in the dial, as hysteria2 does: `fast` marks each member dead, and
/// once the server is the likelier fault, the refusal takes `daniel` down at
/// once, rather than after every member of `fast` is gone.
#[tokio::test]
async fn a_server_that_refuses_every_chain_takes_the_outbound_down() {
    use meow_common::chain_health::BLAMED_MEMBERS;
    let members: Vec<Arc<MockProxy>> = (0..8u16)
        .map(|i| {
            let member = MockProxy::new_failing(
                &format!("M{i}"),
                AdapterType::Hysteria2,
                "remote TCP error: connection refused",
            );
            member.set_delay(10 + i);
            member
        })
        .collect();
    let w = wind_over(
        members
            .iter()
            .map(|m| Arc::clone(m) as Arc<dyn Proxy>)
            .collect(),
    );

    let dials = dials_until_daniel_is_down(&w, 16).await;
    assert_eq!(dials, BLAMED_MEMBERS + 1);
    let alive = members.iter().filter(|m| m.alive()).count();
    assert_eq!(alive, members.len() - dials);
}

/// Block `names` for [`target`] in `fast`'s chain health, as an earlier
/// outage of the server would have.
fn blocked_before(w: &Wind, names: &[&str]) {
    let health = w.fast.chain_health().unwrap();
    for name in names {
        for _ in 0..meow_common::chain_health::PASSIVE_STRIKES {
            health.record_failed(&target(), name, ChainVerdict::Passive, CLOSED_BEFORE_REPLY);
        }
        assert!(health.is_blocked(&target(), name));
    }
}

/// The server closing every chain again while a member is still blocked
/// from its last outage: once the other members are blocked too, `fast`
/// dials its own pick with nowhere else to go, and those failures count
/// against `daniel`, although no 4th member failed it in a row.
#[tokio::test]
async fn a_server_that_closes_every_chain_takes_the_outbound_down_with_members_left_blocked() {
    use super::test_support::StreamProxy;
    use meow_common::chain_health::{BLAMED_MEMBERS, PASSIVE_STRIKES};
    let members: Vec<Arc<StreamProxy>> = (0..=BLAMED_MEMBERS as u16)
        .map(|i| {
            let member =
                StreamProxy::auditing(&format!("M{i}"), &format!("10.0.0.{}:443", i + 1), 8443);
            member.set_delay(10 + i);
            member
        })
        .collect();
    let w = wind_over(
        members
            .iter()
            .map(|m| Arc::clone(m) as Arc<dyn Proxy>)
            .collect(),
    );
    blocked_before(&w, &[&format!("M{BLAMED_MEMBERS}")]);

    let dials = dials_until_daniel_is_down(&w, 32).await;
    assert_eq!(
        dials,
        BLAMED_MEMBERS * usize::from(PASSIVE_STRIKES) + DIAL_FAILURE_THRESHOLD as usize
    );
    assert_eq!(
        members[BLAMED_MEMBERS].dials(),
        0,
        "the member blocked before is not dialled"
    );
}

/// Every member of `fast` blocked for the server, and the server's chains
/// failing in the dial: the member `fast` takes anyway is its last resort,
/// so the failures count against `daniel` at once rather than after
/// `fast` marks members dead one by one.
#[tokio::test]
async fn a_failed_dial_through_a_last_resort_member_counts_against_the_outbound() {
    let members: Vec<Arc<MockProxy>> = (0..4u16)
        .map(|i| {
            let member = MockProxy::new_failing(&format!("M{i}"), AdapterType::Vless, "early eof");
            member.set_delay(10 + i);
            member
        })
        .collect();
    let w = wind_over(
        members
            .iter()
            .map(|m| Arc::clone(m) as Arc<dyn Proxy>)
            .collect(),
    );
    blocked_before(&w, &["M0", "M1", "M2", "M3"]);

    let dials = dials_until_daniel_is_down(&w, 12).await;
    assert_eq!(dials, DIAL_FAILURE_THRESHOLD as usize);
}
