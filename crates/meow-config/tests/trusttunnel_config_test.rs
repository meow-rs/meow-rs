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
}

fn unsupported_node() -> HashMap<String, serde_yaml::Value> {
    // Enabled H2 builds must reject an H3 request; disabled builds must
    // reject the protocol itself. Both must fail the containing config.
    node("quic: true\n")
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
async fn unsupported_node_rejects_load_and_rebuild_even_in_lenient_mode() {
    let document = format!(
        "{}proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [fixture, DIRECT]\nrules: ['MATCH,PROXY']\n",
        serde_yaml::to_string(&HashMap::from([("proxies", vec![unsupported_node()])])).unwrap()
    );
    let error = meow_config::load_config_from_str(&document)
        .await
        .err()
        .expect("dropping TT must not let the group select DIRECT");
    assert!(error.to_string().contains("trusttunnel"), "{error}");
    assert!(!error.to_string().contains("test-only"));

    let raw = meow_config::parse_raw_yaml(&document).unwrap();
    let error = meow_config::rebuild_from_raw(&raw)
        .err()
        .expect("runtime rebuild must reject the same node");
    assert!(error.to_string().contains("trusttunnel"), "{error}");
}

#[tokio::test]
async fn unsupported_provider_node_preserves_last_good_generation() {
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

    let error = provider
        .refresh()
        .await
        .expect_err("a valid sibling must not mask a rejected TT node");
    assert!(error.contains("trusttunnel"), "{error}");
    let current = provider.proxies();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].name(), "last-good");
    assert!(std::sync::Arc::ptr_eq(&previous[0], &current[0]));
    assert_eq!(provider.updated_at_secs(), updated_at);
}

#[tokio::test]
async fn unsupported_provider_node_rejects_initial_config_load() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.yaml");
    std::fs::write(&path, provider_document()).unwrap();
    let result = meow_config::proxy_provider::load_proxy_providers(
        &HashMap::from([("fixture".into(), file_provider(&path))]),
        Some(directory.path()),
        false,
        false,
        &meow_proxy::dialer::ProxyRegistry::default(),
    )
    .await;
    let error = result
        .err()
        .expect("initial TT parse errors must propagate");
    assert!(error.to_string().contains("trusttunnel"), "{error}");
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

    #[test]
    fn unsupported_transport_and_tls_policies_are_explicit_errors() {
        for (extra, expected) in [
            ("quic: true\n", "HTTP/3"),
            ("alpn: [http/1.1]\n", "alpn"),
            ("fingerprint: 00\n", "fingerprint"),
            ("ech-opts: {}\n", "ech-opts"),
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
