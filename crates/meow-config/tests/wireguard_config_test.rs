//! WireGuard parser contracts (`type: wireguard` / `type: WireGuard`,
//! issue #899 Phase-1). Mirrored on the TrustTunnel two-mode contract:
//! the feature-off leg asserts the named "not compiled into this build"
//! error; everything else is `#[cfg(feature = "wireguard")]`-gated.

use std::collections::HashMap;

const PRIVATE_KEY: &str = "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=";
const PUBLIC_KEY: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
#[cfg(feature = "wireguard")]
const PRE_SHARED_KEY: &str = "sWrYKUBHgEMJ9xQKbW7OpZQbCVhDfkFI4qw/iyxImIM=";
/// 32 zero bytes — [`meow_proxy::WireGuardAdapter::new`] refuses an
/// all-zero key even though base64 decodes it cleanly.
#[cfg(feature = "wireguard")]
const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Serialize with the same options `save_raw_config` uses (saphyr's default
/// would re-wrap >80-char scalars into `>`-folded blocks).
#[cfg(feature = "wireguard")]
fn to_yaml<T: serde::Serialize>(value: &T) -> String {
    serde_saphyr::to_string_with_options(
        value,
        serde_saphyr::ser_options! { folded_wrap_chars: usize::MAX },
    )
    .unwrap()
}

fn node(extra: &str) -> HashMap<String, serde_json::Value> {
    node_with_ip("ip: 172.16.0.2\n", extra)
}

/// Same node but the `ip:` key comes from `extra` only — needed by tests
/// that vary the tunnel addresses (YAML forbids duplicate mapping keys).
#[cfg(feature = "wireguard")]
fn node_noip(extra: &str) -> HashMap<String, serde_json::Value> {
    node_with_ip("", extra)
}

fn node_with_ip(ip_line: &str, extra: &str) -> HashMap<String, serde_json::Value> {
    serde_saphyr::from_str(&format!(
        "name: fixture\ntype: wireguard\nserver: engage.cloudflareclient.com\nport: 2408\n{ip_line}private-key: \"{PRIVATE_KEY}\"\npublic-key: \"{PUBLIC_KEY}\"\n{extra}"
    ))
    .unwrap()
}

#[cfg(not(feature = "wireguard"))]
#[test]
fn disabled_protocol_fails_node_parsing() {
    for spelling in ["wireguard", "WireGuard"] {
        let mut config = node("");
        config.insert("type".into(), spelling.into());
        let error = meow_config::proxy_parser::parse_proxy(&config, false)
            .err()
            .unwrap();
        assert!(error.contains("wireguard"), "{spelling}: {error}");
        assert!(error.contains("not compiled into this build"), "{error}");
        assert!(error.contains("--features wireguard"), "{error}");
    }
}

#[cfg(feature = "wireguard")]
mod enabled {
    use super::{node, node_noip, to_yaml, PRE_SHARED_KEY, ZERO_KEY};
    use meow_common::AdapterType;
    use meow_config::proxy_parser::{
        parse_proxy, parse_proxy_provider_node, parse_proxy_with_dialer,
    };
    use meow_proxy::dialer::{
        DialerTarget, DirectDialer, NamedProxyDialer, ProxyRegistry, TcpDialer,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A complete mihomo-compatible block (Cloudflare WARP shape — the
    /// `reserved` identifier is what WARP needs). `ip` is already in the
    /// base node; YAML forbids duplicate keys.
    const FULL: &str = "ipv6: \"fd01:5ca1:ab1e:80fa:ab63:6eea:8f63:f386\"\nmtu: 1420\nudp: true\nremote-dns-resolve: true\npersistent-keepalive: 25\nreserved: [13, 53, 133]\npre-shared-key: \"sWrYKUBHgEMJ9xQKbW7OpZQbCVhDfkFI4qw/iyxImIM=\"\nallowed-ips: [0.0.0.0/0, \"::/0\"]\nip-stack: gvisor\n";

    #[test]
    fn valid_wireguard_config_parses_correctly() {
        let proxy = parse_proxy(&node(FULL), false).unwrap();
        assert_eq!(proxy.name(), "fixture");
        assert_eq!(proxy.adapter_type(), AdapterType::WireGuard);
        assert_eq!(proxy.addr(), "engage.cloudflareclient.com:2408");
        assert!(proxy.support_udp(), "mihomo's udp default is true");
    }

    #[test]
    fn wireguard_capitalized_type_parses() {
        // mihomo's adapter type constant is "WireGuard"; both spellings load.
        let mut config = node("");
        config.insert("type".into(), "WireGuard".into());
        assert_eq!(
            parse_proxy(&config, false).unwrap().adapter_type(),
            AdapterType::WireGuard
        );
    }

    #[test]
    fn static_and_provider_nodes_share_the_same_adapter_and_defaults() {
        let config = node(FULL);
        let static_node = parse_proxy(&config, false).unwrap();
        let dialer: Arc<dyn TcpDialer> = Arc::new(DirectDialer);
        let provider_node = parse_proxy_provider_node(&config, false, false, &dialer).unwrap();
        for proxy in [static_node, provider_node] {
            assert_eq!(proxy.name(), "fixture");
            assert_eq!(proxy.adapter_type(), AdapterType::WireGuard);
            assert_eq!(proxy.addr(), "engage.cloudflareclient.com:2408");
            assert!(proxy.support_udp());
        }
    }

    #[tokio::test]
    async fn valid_node_survives_full_load_and_rebuild() {
        let document = format!(
            "{}rules: ['MATCH,fixture']\n",
            to_yaml(&HashMap::from([("proxies", vec![node(FULL)])]))
        );
        let config = meow_config::load_config_from_str(&document).await.unwrap();
        assert_eq!(
            config.proxies["fixture"].adapter_type(),
            AdapterType::WireGuard
        );
        let raw = meow_config::parse_raw_yaml(&document).unwrap();
        let rebuilt =
            meow_config::rebuild_from_raw(&raw).expect("runtime rebuild must behave the same way");
        assert_eq!(
            rebuilt.proxies["fixture"].adapter_type(),
            AdapterType::WireGuard
        );
    }

    #[test]
    fn missing_required_fields_name_the_field() {
        for field in ["server", "port", "private-key", "public-key"] {
            let mut config = node("");
            config.remove(field);
            let error = parse_proxy(&config, false).err().unwrap();
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn private_key_wrong_length_is_hard_error() {
        use base64::Engine;
        let mut config = node("");
        config.insert(
            "private-key".into(),
            base64::engine::general_purpose::STANDARD
                .encode([1u8; 31])
                .into(),
        );
        let error = parse_proxy(&config, false).err().unwrap();
        assert!(error.contains("private-key"), "{error}");
        assert!(error.contains("32 bytes"), "{error}");
    }

    #[test]
    fn key_fields_must_be_base64() {
        for field in ["private-key", "public-key", "pre-shared-key"] {
            let mut config = node("");
            config.insert(field.into(), "not base64 !!!".into());
            let error = parse_proxy(&config, false).err().unwrap();
            assert!(error.contains(field), "{field}: {error}");
            assert!(error.contains("base64"), "{field}: {error}");
        }
    }

    #[test]
    fn all_zero_private_key_is_hard_error() {
        let mut config = node("");
        config.insert("private-key".into(), ZERO_KEY.into());
        let error = parse_proxy(&config, false).err().unwrap();
        assert!(error.contains("private_key"), "{error}");
    }

    #[test]
    fn optional_psk_and_keepalive_parse() {
        parse_proxy(
            &node(&format!(
                "pre-shared-key: \"{PRE_SHARED_KEY}\"\npersistent-keepalive: 25\n"
            )),
            false,
        )
        .unwrap();
        parse_proxy(
            &node("pre-shared-key: null\npersistent-keepalive: 0\n"),
            false,
        )
        .unwrap();
    }

    #[test]
    fn amnezia_wg_option_is_hard_error() {
        for extra in [
            "amnezia-wg-option: {}\n",
            "amnezia-wg-option: {jc: 4, jmin: 10}\n",
            "amnezia-wg-option: \"x\"\n",
        ] {
            let error = parse_proxy(&node(extra), false)
                .err()
                .unwrap_or_else(|| panic!("{extra} must not parse"));
            assert!(error.contains("amnezia-wg-option"), "{extra}: {error}");
            assert!(error.contains("not supported"), "{extra}: {error}");
        }
    }

    #[test]
    fn dialer_proxy_is_rejected() {
        // The WG transport owns its UDP endpoint socket, so a TCP dialer
        // chain cannot carry it — `reject_unthreaded_dialer` fires when
        // `apply_dialer_proxies` re-parses the node with the chain's
        // injected dialer (the mihomo model).
        let registry = ProxyRegistry::default();
        let target = DialerTarget::new("front", &registry);
        let dialer: Arc<dyn TcpDialer> =
            Arc::new(NamedProxyDialer::new(target).owned_by("fixture"));
        let error = parse_proxy_with_dialer(&node("dialer-proxy: front\n"), &dialer, false)
            .err()
            .expect("a proxy dialer must be rejected for wireguard");
        assert!(error.contains("dialer-proxy"), "{error}");
    }

    #[test]
    fn reserved_field_wrong_length_is_hard_error() {
        use base64::Engine;
        let bad64 = base64::engine::general_purpose::STANDARD.encode([1u8; 4]);
        for extra in [
            format!("reserved: \"{bad64}\"\n"),
            "reserved: [1, 2]\n".to_string(),
            "reserved: [1, 2, 3, 4]\n".to_string(),
            "reserved: [1, 2, 300]\n".to_string(),
            "reserved: [1, 2, 'x']\n".to_string(),
        ] {
            let error = parse_proxy(&node(&extra), false)
                .err()
                .unwrap_or_else(|| panic!("{extra} must not parse"));
            assert!(error.contains("reserved"), "{extra}: {error}");
        }
    }

    #[test]
    fn reserved_accepts_sequence_and_base64_forms() {
        // The Cloudflare WARP identifier: `[13, 53, 133]` and its base64
        // "DTWF" are the same bytes; quoted or bare both work.
        for extra in [
            "reserved: [13, 53, 133]\n",
            "reserved: \"DTWF\"\n",
            "reserved: DTWF\n",
            "reserved: null\n",
        ] {
            parse_proxy(&node(extra), false).unwrap_or_else(|e| panic!("{extra}: {e}"));
        }
    }

    #[test]
    fn dns_field_is_accepted_with_warning() {
        // Phase-1 stores `dns` and warns once per parse; the warning is a
        // log, so the contract asserted here is "parses and loads".
        for extra in [
            "dns: [1.1.1.1, tls://8.8.8.8]\n",
            "dns: 1.1.1.1\n",
            "dns: []\n",
            "dns: ~\n",
        ] {
            parse_proxy(&node(extra), false).unwrap_or_else(|e| panic!("{extra}: {e}"));
        }
    }

    #[test]
    fn dns_field_rejects_bad_types() {
        for extra in ["dns: [1, 2]\n", "dns: {a: b}\n"] {
            let error = parse_proxy(&node(extra), false).err().unwrap();
            assert!(error.contains("dns"), "{extra}: {error}");
        }
    }

    #[test]
    fn ip_stack_follows_the_phase1_contract() {
        // `gvisor` maps silently onto the built-in smoltcp stack; `system`
        // warns once and maps too. Everything else — including mihomo's
        // `{mode, congestion-controller}` object form — is a named error.
        for extra in [
            "ip-stack: gvisor\n",
            "ip-stack: system\n",
            "ip-stack: \"\"\n",
        ] {
            parse_proxy(&node(extra), false).unwrap_or_else(|e| panic!("{extra}: {e}"));
        }
        for extra in [
            "ip-stack: mips\n",
            "ip-stack: lwip\n",
            "ip-stack: mixed\n",
            "ip-stack: auto\n",
            "ip-stack: {mode: gvisor}\n",
            "ip-stack: 1\n",
        ] {
            let error = parse_proxy(&node(extra), false)
                .err()
                .unwrap_or_else(|| panic!("{extra} must not parse"));
            assert!(error.contains("ip-stack"), "{extra}: {error}");
        }
    }

    #[test]
    fn allowed_ips_parse_and_validate() {
        for extra in [
            "allowed-ips: [0.0.0.0/0, \"::/0\"]\n",
            "allowed-ips: [10.0.0.0/8, 192.168.0.0/16, \"fd00::/8\"]\n",
            // Absent or empty: the adapter applies the catch-all default.
            "allowed-ips: []\n",
        ] {
            parse_proxy(&node(extra), false).unwrap_or_else(|e| panic!("{extra}: {e}"));
        }
        for extra in [
            "allowed-ips: [not-a-cidr]\n",
            "allowed-ips: [10.0.0.0/33]\n",
            "allowed-ips: not-a-list\n",
            "allowed-ips: [1, 2]\n",
        ] {
            let error = parse_proxy(&node(extra), false)
                .err()
                .unwrap_or_else(|| panic!("{extra} must not parse"));
            assert!(error.contains("allowed-ips"), "{extra}: {error}");
        }
    }

    #[test]
    fn tunnel_addresses_accept_bare_ip_or_cidr() {
        for extra in [
            "ip: 10.0.0.2\n",
            "ip: 10.0.0.2/24\n",
            "ipv6: fd00::2\n",
            "ipv6: fd00::2/64\n",
            "ip: 10.0.0.2\nipv6: fd00::2/64\n",
        ] {
            parse_proxy(&node_noip(extra), false).unwrap_or_else(|e| panic!("{extra}: {e}"));
        }
        for (extra, needle) in [
            ("ip: not-an-ip\n", "'ip'"),
            ("ip: 10.0.0.0/99\n", "'ip'"),
            ("ip: \"::1\"\n", "'ip' must be IPv4"),
            ("ipv6: 1.2.3.4\n", "'ipv6' must be IPv6"),
            ("ipv6: not-an-ip\n", "'ipv6'"),
        ] {
            let error = parse_proxy(&node_noip(extra), false)
                .err()
                .unwrap_or_else(|| panic!("{extra} must not parse"));
            assert!(error.contains(needle), "{extra}: {error}");
        }
    }

    #[test]
    fn mtu_and_keepalive_bounds() {
        // `mtu` outer range per the spec table is 576–9000; the adapter
        // additionally requires inner MTU ≥ 576 (mtu ≥ 640), so 576–639
        // is a hard error from the adapter's own message.
        for extra in [
            "mtu: 575\n",
            "mtu: 576\n",
            "mtu: 639\n",
            "mtu: 9001\n",
            "mtu: \"1400\"\n",
            "persistent-keepalive: 70000\n",
            "persistent-keepalive: \"x\"\n",
        ] {
            let error = parse_proxy(&node(extra), false)
                .err()
                .unwrap_or_else(|| panic!("{extra} must not parse"));
            assert!(
                error.contains("mtu") || error.contains("persistent-keepalive"),
                "{extra}: {error}"
            );
        }
        for extra in [
            "mtu: 640\n",
            "mtu: 1420\n",
            "mtu: 9000\n",
            "persistent-keepalive: 25\n",
            "persistent-keepalive: 0\n",
        ] {
            parse_proxy(&node(extra), false).unwrap_or_else(|e| panic!("{extra}: {e}"));
        }
    }

    #[test]
    fn udp_and_remote_dns_resolve_flags() {
        // Defaults match mihomo: udp true, remote-dns-resolve true.
        assert!(parse_proxy(&node(""), false).unwrap().support_udp());
        assert!(!parse_proxy(&node("udp: false\n"), false)
            .unwrap()
            .support_udp());
        parse_proxy(&node("remote-dns-resolve: false\n"), false).unwrap();
        for field in ["udp", "remote-dns-resolve"] {
            for extra in [format!("{field}: 'true'\n"), format!("{field}: [1]\n")] {
                let error = parse_proxy(&node(&extra), false)
                    .err()
                    .unwrap_or_else(|| panic!("{extra} must not parse"));
                assert!(error.contains(field), "{extra}: {error}");
            }
        }
    }

    #[test]
    fn no_tunnel_address_still_parses_with_a_warning() {
        // ip+ipv6 both absent: the adapter logs a construction warning
        // (smoltcp cannot pick a TCP source address) but IP-literal flows
        // can still work — the spec keeps this a warn, not an error.
        let mut config = node("");
        config.remove("ip");
        parse_proxy(&config, false).expect("missing tunnel addrs is warn-only");
        config.insert("remote-dns-resolve".into(), false.into());
        parse_proxy(&config, false).expect("remote-dns-resolve: false too");
    }
}
