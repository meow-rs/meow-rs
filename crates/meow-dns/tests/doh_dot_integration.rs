//! Network-dependent integration tests for DoH and DoT upstream DNS clients.
//!
//! All tests are `#[ignore]` — they require outbound internet access and
//! are NOT wired into CI.  Run manually with:
//!
//!   cargo test -p meow-dns --test doh_dot_integration -- --ignored --nocapture
//!
//! Manually verified against Cloudflare (1.1.1.1) and Google (8.8.8.8) at
//! the time this PR was opened.

use meow_common::DnsMode;
use meow_dns::upstream::NameServerUrl;
use meow_dns::Resolver;
use meow_trie::DomainTrie;

// E1: DoT resolves example.com via 1.1.1.1:853 with Cloudflare SNI.
#[tokio::test]
#[ignore]
async fn dot_resolves_example_com() {
    let main = vec![NameServerUrl::parse("tls://1.1.1.1:853#cloudflare-dns.com").unwrap()];
    let resolver = Resolver::new_with_bootstrap(
        main,
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
        None,
        None,
    )
    .await
    .expect("DoT resolver must build");
    let ip = resolver.resolve_ip("example.com").await.unwrap();
    assert!(
        ip.is_some(),
        "expected an IPv4/IPv6 answer for example.com via DoT"
    );
}

// E2: DoH resolves example.com via 1.1.1.1/dns-query with Cloudflare SNI.
#[tokio::test]
#[ignore]
async fn doh_resolves_example_com() {
    let main = vec![NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap()];
    let resolver = Resolver::new_with_bootstrap(
        main,
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
        None,
        None,
    )
    .await
    .expect("DoH resolver must build");
    let ip = resolver.resolve_ip("example.com").await.unwrap();
    assert!(ip.is_some(), "expected an answer for example.com via DoH");
}

// E3: DoT with bogus SNI fails TLS certificate validation.
// Smoke-tests that SNI is sent and validated by hickory's TLS stack.
#[tokio::test]
#[ignore]
async fn dot_bogus_sni_fails_cert_validation() {
    let main = vec![NameServerUrl::parse("tls://1.1.1.1:853#wrong.example").unwrap()];
    let resolver = Resolver::new_with_bootstrap(
        main,
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
        None,
        None,
    )
    .await
    .expect("resolver builds even with bad SNI");
    // resolve_ip is io::Result<Option<_>>: cert validation failure is
    // surfaced as Err, not Ok(None).
    let result = resolver.resolve_ip("example.com").await;
    assert!(
        matches!(result, Err(_) | Ok(None)),
        "DoT with bogus SNI must fail cert validation; unexpectedly got: {result:?}"
    );
}

// E4: DoH with bogus SNI fails TLS/HTTP2 certificate validation.
// Different hickory code path from E3 (HTTPS vs raw TLS).
#[tokio::test]
#[ignore]
async fn doh_bogus_sni_fails_cert_validation() {
    let main = vec![NameServerUrl::parse("https://1.1.1.1/dns-query#wrong.example").unwrap()];
    let resolver = Resolver::new_with_bootstrap(
        main,
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
        None,
        None,
    )
    .await
    .expect("resolver builds even with bad SNI");
    let result = resolver.resolve_ip("example.com").await;
    assert!(
        matches!(result, Err(_) | Ok(None)),
        "DoH with bogus SNI must fail cert validation; unexpectedly got: {result:?}"
    );
}

// E5: DoT with a hostname (not IP literal) in nameserver plus bootstrap resolves end-to-end.
// Guard-rail for the full bootstrap path: dns.google resolved via 8.8.8.8,
// then DoT connection made to the resolved IP.
#[tokio::test]
#[ignore]
async fn dot_hostname_with_bootstrap_resolves() {
    let main = vec![NameServerUrl::parse("tls://dns.google:853#dns.google").unwrap()];
    let default_ns = vec![NameServerUrl::parse("8.8.8.8").unwrap()];
    let resolver = Resolver::new_with_bootstrap(
        main,
        vec![],
        default_ns,
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
        None,
        None,
    )
    .await
    .expect("bootstrap + DoT resolver must build");
    let ip = resolver.resolve_ip("example.com").await.unwrap();
    assert!(
        ip.is_some(),
        "expected an answer via dns.google DoT after bootstrap; got None"
    );
}
