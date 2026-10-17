//! TrustTunnel parser contracts, shared by static and provider nodes.

use std::collections::HashMap;

fn node(extra: &str) -> HashMap<String, serde_yaml::Value> {
    serde_yaml::from_str(&format!(
        "name: fixture\ntype: trusttunnel\nserver: vpn.example.test\nport: 443\nusername: fixture\npassword: test-only\n{extra}"
    ))
    .unwrap()
}

#[cfg(not(feature = "trusttunnel"))]
#[test]
fn disabled_protocol_fails_node_parsing() {
    let error = meow_config::proxy_parser::parse_proxy(&node(""), false)
        .err()
        .unwrap();
    assert!(error.contains("trusttunnel"));
    assert!(error.contains("not compiled into this build"));
    assert!(error.contains("--features trusttunnel"));
}

fn unsupported_node() -> HashMap<String, serde_yaml::Value> {
    // Enabled builds must reject a TLS policy they do not implement;
    // disabled builds must reject the protocol itself. Either way the name
    // has to stay bound to something that cannot dial, rather than
    // disappearing.
    node("fingerprint: 00\n")
}

/// Every assertion below is the same contract: the node's own slot survives
/// as a permanently dead entry, so a group listing it can neither shift the
/// traffic to a sibling nor fall through to a direct dial, and the dial error
/// names the node without quoting its credentials.
async fn assert_unavailable(proxy: &std::sync::Arc<dyn meow_common::Proxy>) {
    assert!(!proxy.alive(), "a placeholder must never look usable");
    // The declared type, dead — not `Reject`. Reporting `Reject` would make
    // the misconfiguration this placeholder exists to surface look like an
    // intentional one in `/proxies`, in the tunnel's match statistics, and in
    // the group dial-failure exemptions.
    assert_eq!(
        proxy.adapter_type(),
        meow_common::AdapterType::TrustTunnel,
        "a placeholder must keep the node's own type"
    );
    let error = proxy
        .dial_tcp(&meow_common::Metadata::default())
        .await
        .err()
        .expect("a placeholder must fail the dial, not leak it direct")
        .to_string();
    assert!(error.contains(proxy.name()), "{error}");
    assert!(!error.contains("test-only"), "{error}");
    // UDP included: a target without UDP support is *skipped* by the rule
    // engine, which then falls through to a later rule or DIRECT. So the
    // placeholder advertises UDP and refuses the association instead.
    assert!(
        proxy.support_udp(),
        "a placeholder that declines UDP lets the rule engine skip it to DIRECT"
    );
    let error = proxy
        .dial_udp(&meow_common::Metadata::default())
        .await
        .err()
        .expect("a placeholder must fail the UDP dial too")
        .to_string();
    assert!(error.contains(proxy.name()), "{error}");
    assert!(!error.contains("test-only"), "{error}");
}

#[cfg(feature = "trusttunnel")]
#[test]
fn user_agent_and_header_fields_are_accepted() {
    // `platform` / `app-name` are the spec's two user-agent fields, and
    // `headers:` rides on every CONNECT with Surge's own padding syntax.
    meow_config::proxy_parser::parse_proxy(
        &node(
            "platform: ios\napp-name: AdGuard VPN\nheaders:\n  X-Padding: \"<random-string(16-32)>\"\n  X-Fixed: constant\n",
        ),
        false,
    )
    .expect("the fingerprint knobs must parse");
    // Absent, null and empty-map declarations keep the defaults.
    meow_config::proxy_parser::parse_proxy(
        &node("platform: null\napp-name: null\nheaders: null\n"),
        false,
    )
    .expect("nulls must stay inert, as every other optional field is");
}

#[cfg(feature = "trusttunnel")]
#[test]
fn malformed_user_agent_and_header_fields_name_the_defect() {
    for (extra, needle) in [
        ("platform: \"i os\"\n", "platform cannot contain whitespace"),
        ("app-name: \"\"\n", "app-name is empty"),
        // A field value that starts or ends with SP/HTAB is malformed
        // (RFC 9113 §8.2.1); `app-name` ends the `user-agent` value.
        (
            "app-name: \"AdGuard \"\n",
            "app-name cannot start or end with whitespace",
        ),
        (
            "headers:\n  X-Pad: \" abc\"\n",
            "cannot start with a space or tab",
        ),
        (
            "headers:\n  X-Pad: \"abc\\t\"\n",
            "cannot end with a space or tab",
        ),
        // A placeholder that can render empty exposes its neighbour's edge.
        (
            "headers:\n  X-Pad: \"abc <random-string(0-8)>\"\n",
            "cannot end with a space or tab",
        ),
        ("headers: [one, two]\n", "headers must be a map"),
        ("headers:\n  X-Pad: 7\n", "header 'X-Pad' must be a string"),
        (
            "headers:\n  X-Pad: \"<random-string(32>\"\n",
            "unterminated",
        ),
        ("headers:\n  X-Pad: \"<random-string(9-4)>\"\n", "inverted"),
        (
            "headers:\n  proxy-authorization: \"Basic x\"\n",
            "set by the adapter itself",
        ),
        ("headers:\n  \"bad name\": ok\n", "is not a header name"),
        // Connection-specific headers are illegal on HTTP/2 and HTTP/3
        // (RFC 9113 §8.2.2 / RFC 9114 §4.2) — and `connection: keep-alive`
        // is exactly what gets added to "look like a browser". A receiver
        // resets the stream, which would surface as this node failing.
        (
            "headers:\n  Connection: keep-alive\n",
            "would treat the CONNECT as malformed",
        ),
        (
            "headers:\n  Transfer-Encoding: chunked\n",
            "would treat the CONNECT as malformed",
        ),
        // One header, two spellings: it would be sent twice.
        (
            "headers:\n  User-Agent: a\n  user-agent: b\n",
            "declared twice",
        ),
    ] {
        let error = meow_config::proxy_parser::parse_proxy(&node(extra), false)
            .err()
            .unwrap_or_else(|| panic!("{extra} must not parse"));
        assert!(error.contains(needle), "{extra} -> {error}");
        assert!(!error.contains("test-only"), "{error}");
    }
}

#[cfg(feature = "trusttunnel")]
#[test]
fn optional_null_and_empty_policy_fields_use_defaults() {
    let config = node("udp: null\nsni: null\nskip-cert-verify: null\nhealth-check: null\nmax-connections: null\nmin-streams: null\nmax-streams: null\nname-cert-verify: null\nclient-fingerprint: null\nalpn: []\nfingerprint: null\ncertificate: ''\nech-opts: {}\nbbr-opts: null\n");
    meow_config::proxy_parser::parse_proxy(&config, false)
        .expect("optional nulls and inert declarations must not reject generated subscriptions");
}

#[tokio::test]
async fn initial_acquisition_binds_an_unavailable_node_instead_of_rejecting_the_feed() {
    use meow_config::proxy_provider::ProxyProvider;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bad.yaml");
    std::fs::write(&path, provider_document()).unwrap();
    let provider = ProxyProvider::new(
        "p",
        &file_provider(&path),
        Some(directory.path()),
        false,
        false,
        Default::default(),
    )
    .unwrap();
    provider
        .acquire_initial()
        .await
        .expect("one unusable node must not empty a third-party feed");
    let proxies = provider.proxies();
    assert_eq!(proxies.len(), 2, "the slot entry has to survive");
    let bad = proxies
        .iter()
        .find(|proxy| proxy.name() == "fixture")
        .expect("the TT name stays addressable");
    assert_unavailable(bad).await;

    // Strict mode is the opt-in that *does* reject the payload: there the
    // operator has asked for every defect to be fatal.
    let strict = ProxyProvider::new(
        "p-strict",
        &file_provider(&path),
        Some(directory.path()),
        false,
        true,
        Default::default(),
    )
    .unwrap();
    let error = strict
        .acquire_initial()
        .await
        .expect_err("strict mode must still reject an unparseable node");
    assert!(error.to_string().contains("strict mode"), "{error:#}");
}

#[tokio::test]
async fn whitespace_type_still_lands_on_the_fail_closed_path() {
    let mut config = unsupported_node();
    config.insert("type".into(), "trusttunnel ".into());
    let raw = meow_config::raw::RawConfig {
        proxies: Some(vec![config]),
        ..Default::default()
    };
    // A padded type name is treated as TT by the gate, so it must get the
    // same dead placeholder rather than silently vanishing from `proxies:`.
    let rebuilt = meow_config::rebuild_from_raw(&raw).unwrap();
    assert_unavailable(&rebuilt.proxies["fixture"]).await;
}

fn provider_document() -> String {
    serde_yaml::to_string(&serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter(
        [(
            serde_yaml::Value::String("proxies".into()),
            serde_yaml::Value::Sequence(vec![
                serde_yaml::from_str("name: sibling\ntype: http\nserver: 127.0.0.1\nport: 8080\n")
                    .unwrap(),
                serde_yaml::to_value(unsupported_node()).unwrap(),
            ]),
        )],
    )))
    .unwrap()
}

fn file_provider(path: &std::path::Path) -> meow_config::raw::RawProxyProvider {
    serde_yaml::from_value(serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter(
        [
            (
                serde_yaml::Value::String("type".into()),
                serde_yaml::Value::String("file".into()),
            ),
            (
                serde_yaml::Value::String("path".into()),
                serde_yaml::Value::String(path.to_str().unwrap().into()),
            ),
        ],
    )))
    .unwrap()
}

#[tokio::test]
async fn unsupported_node_stays_bound_so_its_group_cannot_select_direct() {
    let document = format!(
        "{}proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [fixture, DIRECT]\nrules: ['MATCH,PROXY']\n",
        serde_yaml::to_string(&HashMap::from([("proxies", vec![unsupported_node()])])).unwrap()
    );
    // The hole this closes is the group falling back to DIRECT — which
    // needs the name bound to a dead node, not the whole file rejected.
    // Rejecting the file would make an official build that ships without
    // `--features trusttunnel` refuse to start on a config its operator
    // cannot repair by editing anything.
    let config = meow_config::load_config_from_str(&document)
        .await
        .expect("one unusable node must not reject the config");
    assert_unavailable(&config.proxies["fixture"]).await;

    let raw = meow_config::parse_raw_yaml(&document).unwrap();
    let rebuilt =
        meow_config::rebuild_from_raw(&raw).expect("runtime rebuild must behave the same way");
    assert_unavailable(&rebuilt.proxies["fixture"]).await;
}

#[tokio::test]
async fn unsupported_provider_node_refreshes_into_a_dead_placeholder() {
    use meow_config::proxy_provider::ProxyProvider;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.yaml");
    std::fs::write(
        &path,
        "proxies:\n  - {name: last-good, type: http, server: 127.0.0.1, port: 8080}\n",
    )
    .unwrap();
    let provider = ProxyProvider::new(
        "fixture",
        &file_provider(&path),
        Some(directory.path()),
        false,
        false,
        meow_proxy::dialer::ProxyRegistry::default(),
    )
    .unwrap();
    provider.acquire_initial().await.unwrap();
    let previous = provider.proxies();
    let updated_at = provider.updated_at_secs();
    std::fs::write(&path, provider_document()).unwrap();

    provider
        .refresh()
        .await
        .expect("one unusable node must not freeze the whole feed");
    let current = provider.proxies();
    assert_eq!(
        current.len(),
        2,
        "the refreshed payload replaces the old one"
    );
    assert!(
        !std::sync::Arc::ptr_eq(&previous[0], &current[0]),
        "a successful refresh must publish the new generation"
    );
    assert!(provider.updated_at_secs() >= updated_at);
    let bad = current
        .iter()
        .find(|proxy| proxy.name() == "fixture")
        .expect("the TT name stays addressable after a refresh");
    assert_unavailable(bad).await;
}

#[tokio::test]
async fn unsupported_provider_node_does_not_block_the_initial_config_load() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.yaml");
    std::fs::write(&path, provider_document()).unwrap();
    // A third-party payload is refetched on a timer, so a payload-level
    // rejection here would be a daemon-wide kill switch in its operator's
    // hands. Scope the damage to the node instead.
    let providers = meow_config::proxy_provider::load_proxy_providers(
        &HashMap::from([("fixture".into(), file_provider(&path))]),
        Some(directory.path()),
        false,
        false,
        &meow_proxy::dialer::ProxyRegistry::default(),
    )
    .await
    .expect("one unusable node must not stop the daemon from starting");
    let nodes = providers["fixture"].proxies();
    assert_eq!(nodes.len(), 2);
    let bad = nodes
        .iter()
        .find(|proxy| proxy.name() == "fixture")
        .expect("the TT name stays addressable");
    assert_unavailable(bad).await;
}

#[tokio::test]
async fn missing_provider_source_keeps_existing_offline_bootstrap_behavior() {
    let directory = tempfile::tempdir().unwrap();
    let result = meow_config::proxy_provider::load_proxy_providers(
        &HashMap::from([(
            "fixture".into(),
            file_provider(&directory.path().join("missing.yaml")),
        )]),
        Some(directory.path()),
        false,
        false,
        &meow_proxy::dialer::ProxyRegistry::default(),
    )
    .await
    .unwrap();
    assert!(result["fixture"].proxies().is_empty());
}

#[cfg(feature = "trusttunnel")]
mod enabled {
    use super::node;
    use meow_common::AdapterType;
    use meow_config::proxy_parser::{parse_proxy, parse_proxy_provider_node};
    use meow_proxy::dialer::{DirectDialer, TcpDialer};
    use std::sync::Arc;

    #[tokio::test]
    async fn valid_node_survives_full_load_and_rebuild() {
        let document = format!(
            "{}rules: ['MATCH,fixture']\n",
            serde_yaml::to_string(&std::collections::HashMap::from([(
                "proxies",
                vec![node("")]
            )]))
            .unwrap()
        );
        let config = meow_config::load_config_from_str(&document).await.unwrap();
        assert_eq!(
            config.proxies["fixture"].adapter_type(),
            AdapterType::TrustTunnel
        );
        let raw = meow_config::parse_raw_yaml(&document).unwrap();
        let rebuilt = meow_config::rebuild_from_raw(&raw).unwrap();
        assert_eq!(
            rebuilt.proxies["fixture"].adapter_type(),
            AdapterType::TrustTunnel
        );
    }

    #[test]
    fn static_and_provider_nodes_share_the_same_adapter_and_defaults() {
        let config = node("");
        let static_node = parse_proxy(&config, false).unwrap();
        let dialer: Arc<dyn TcpDialer> = Arc::new(DirectDialer);
        let provider_node = parse_proxy_provider_node(&config, false, false, &dialer).unwrap();
        for proxy in [static_node, provider_node] {
            assert_eq!(proxy.name(), "fixture");
            assert_eq!(proxy.adapter_type(), AdapterType::TrustTunnel);
            assert_eq!(proxy.addr(), "vpn.example.test:443");
            assert!(!proxy.support_udp(), "Mihomo's UDP default is false");
            proxy.reset_sessions();
        }
    }

    #[test]
    fn supported_tls_udp_and_pool_settings_parse() {
        for extra in [
            "udp: true\nsni: vpn.example.test\nalpn: [h2]\nname-cert-verify: vpn.example.test\nclient-fingerprint: chrome\nmax-connections: 2\nmin-streams: 5\n",
            "max-connections: 0\nmin-streams: 0\nmax-streams: 0\n",
            "max-connections: 2\nmin-streams: 0\nmax-streams: 9\n",
            "max-streams: 10\n",
        ] {
            assert!(parse_proxy(&node(extra), false).is_ok(), "{extra}");
        }
        assert!(parse_proxy(&node("udp: true\n"), false)
            .unwrap()
            .support_udp());
    }

    #[test]
    fn ipv6_endpoint_address_retains_unambiguous_host_and_port() {
        let mut config = node("");
        config.insert(
            "server".into(),
            serde_yaml::Value::String("2001:db8::1".into()),
        );
        let proxy = parse_proxy(&config, false).unwrap();
        assert_eq!(proxy.addr(), "[2001:db8::1]:443");
    }

    #[test]
    fn malformed_fields_and_resource_limits_fail_before_dialing() {
        for (extra, expected) in [
            ("udp: 'true'\n", "udp"),
            ("health-check: 1\n", "health-check"),
            ("quic: 'false'\n", "quic"),
            ("sni: 12\n", "sni"),
            ("name-cert-verify: false\n", "name-cert-verify"),
            ("client-fingerprint: []\n", "client-fingerprint"),
            ("max-connections: 17\n", "pool limits"),
            ("min-streams: -1\n", "min-streams"),
            ("max-streams: 513\n", "pool limits"),
        ] {
            let error = parse_proxy(&node(extra), false).err().unwrap();
            assert!(error.contains(expected), "{extra}: {error}");
        }
    }

    /// `quic: true` is the HTTP/3 transport, behind its own feature because
    /// quiche is not in an H2-only build's dependency graph at all.
    #[cfg(not(feature = "trusttunnel-h3"))]
    #[test]
    fn quic_names_the_feature_that_carries_it() {
        let error = parse_proxy(&node("quic: true\n"), false).err().unwrap();
        assert!(error.contains("HTTP/3"), "{error}");
        assert!(error.contains("--features trusttunnel-h3"), "{error}");
    }

    #[cfg(feature = "trusttunnel-h3")]
    #[test]
    fn quic_nodes_parse_and_refuse_what_h3_cannot_honor() {
        for extra in [
            "quic: true\n",
            "quic: true\nalpn: [h3]\nudp: true\nsni: vpn.example.test\nskip-cert-verify: true\n",
            "quic: true\nmax-connections: 2\nmin-streams: 1\nplatform: ios\napp-name: Surge\n",
        ] {
            assert!(parse_proxy(&node(extra), false).is_ok(), "{extra}");
        }
        // The transport decides the ALPN, so each one rejects the other's.
        for (extra, expected) in [
            ("quic: true\nalpn: [h2]\n", "alpn: [h3]"),
            ("alpn: [h3]\n", "alpn: [h2]"),
            (
                "quic: true\nclient-fingerprint: chrome\n",
                "client-fingerprint",
            ),
            (
                "quic: true\nname-cert-verify: other.test\n",
                "name-cert-verify",
            ),
        ] {
            let error = parse_proxy(&node(extra), false).err().unwrap();
            assert!(error.contains(expected), "{extra}: {error}");
        }
    }

    #[test]
    fn unsupported_transport_and_tls_policies_are_explicit_errors() {
        for (extra, expected) in [
            ("alpn: [http/1.1]\n", "alpn"),
            ("fingerprint: 00\n", "fingerprint"),
            ("ech-opts: {enable: true}\n", "ech-opts"),
            ("certificate: client.pem\n", "certificate"),
            ("congestion-controller: cubic\n", "congestion-controller"),
            ("cwnd: 10\n", "cwnd"),
        ] {
            let config = node(extra);
            let error = parse_proxy(&config, false).err().unwrap();
            assert!(error.contains(expected), "{extra}: {error}");
            let dialer: Arc<dyn TcpDialer> = Arc::new(DirectDialer);
            assert!(parse_proxy_provider_node(&config, false, false, &dialer).is_err());
        }
    }

    #[test]
    fn invalid_required_fields_fail_without_leaking_credentials() {
        for field in ["name", "server", "port", "username", "password"] {
            let mut config = node("");
            config.remove(field);
            let error = parse_proxy(&config, false).err().unwrap();
            assert!(error.contains(field), "{field}: {error}");
            assert!(!error.contains("test-only"));
        }
    }
}

#[test]
fn padded_trusttunnel_type_names_explain_the_whitespace_defect() {
    let mut raw = node("");
    raw.insert(
        "type".into(),
        serde_yaml::Value::String(" TrustTunnel ".into()),
    );
    let error = meow_config::proxy_parser::parse_proxy(&raw, false)
        .err()
        .unwrap();
    assert!(error.contains("surrounding whitespace"));
    assert!(error.contains("trusttunnel"));
}
