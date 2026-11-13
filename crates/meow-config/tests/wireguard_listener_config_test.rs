//! WireGuard *listener* schema contracts (`listeners:` entry `type: wireguard`).
//!
//! The typed `ListenerSpec::WireGuard` variant parses on every build — the
//! config schema carries no feature gate; servability is enforced at
//! runtime by the `listener-wireguard` build feature
//! (`ensure_listeners_supported`), the same shape as `type: shadowsocks`
//! vs. `listener-shadowsocks`.
//!
//! Feature note: the "peer public-key == listener's own public key" check
//! runs at config time only when the `wireguard` feature is compiled — its
//! `dep:x25519-dalek` supplies the basepoint multiply. Both legs are pinned
//! below; on other builds the listener startup path re-checks.

use meow_config::{load_config_from_str, ListenerSpec};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

/// RFC 7748 Alice scalar — a real X25519 private key.
const LISTENER_PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
/// `X25519(LISTENER_PRIV, basepoint)` — the listener's own public key.
const LISTENER_PUB: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
/// RFC 7748 Bob public — a valid peer public key.
const PEER_PUB: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
/// A second, distinct peer public key.
const PEER_PUB2: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
/// A 32-byte pre-shared key.
const PSK: &str = "SrVrR+zcag84suKzo+kODI6fHSo7TF1uf4CRorPE1eY=";
/// 32 zero bytes — decodes cleanly but is not a valid WG key.
const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// 16 bytes — base64-decodes but fails the 32-byte rule.
const SHORT_B64: &str = "MDEyMzQ1Njc4OTAxMjM0NQ==";

/// One `peers:` item; `extra` is appended verbatim (8-space indent).
fn peer(extra: &str) -> String {
    format!("      - public-key: \"{PEER_PUB}\"\n        allowed-ips: [10.0.0.0/8]\n{extra}")
}

/// A `listeners:` document with one `type: wireguard` entry; `extra`
/// fields splice in at 4-space indent (empty string = minimal form).
fn wg_yaml(listener_extra: &str, peers_yaml: &str) -> String {
    format!(
        "listeners:\n  - name: wg-in\n    type: wireguard\n    listen: 127.0.0.1:0\n    private-key: \"{LISTENER_PRIV}\"\n{listener_extra}    peers:\n{peers_yaml}"
    )
}

fn minimal_yaml() -> String {
    wg_yaml("", &peer(""))
}

/// Extract the `WgListenerConfig` of the single named listener.
async fn build_wg(yaml: &str) -> meow_config::WgListenerConfig {
    let config = load_config_from_str(yaml)
        .await
        .unwrap_or_else(|e| panic!("config must load: {e:#}\nyaml:\n{yaml}"));
    assert_eq!(config.listeners.named.len(), 1);
    let nl = &config.listeners.named[0];
    let ListenerSpec::WireGuard(cfg) = &nl.spec else {
        panic!("expected ListenerSpec::WireGuard, got {:?}", nl.spec);
    };
    cfg.clone()
}

async fn err_of(yaml: &str) -> String {
    match load_config_from_str(yaml).await {
        Err(e) => format!("{e:#}"),
        Ok(_) => panic!("config must fail to load\nyaml:\n{yaml}"),
    }
}

// ─── Warn-capture helper (same shape as vless_config_test's) ─────────────

#[derive(Clone)]
struct CapWriter {
    lines: Arc<Mutex<Vec<String>>>,
    buf: Arc<Mutex<String>>,
}

impl CapWriter {
    fn new() -> Self {
        Self {
            lines: Arc::new(Mutex::new(Vec::new())),
            buf: Arc::new(Mutex::new(String::new())),
        }
    }

    fn captured(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

impl std::io::Write for CapWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(data);
        let mut b = self.buf.lock().unwrap();
        b.push_str(&s);
        if b.contains('\n') {
            let mut log = self.lines.lock().unwrap();
            for line in b.split('\n') {
                let t = line.trim();
                if !t.is_empty() {
                    log.push(t.to_string());
                }
            }
            b.clear();
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

async fn load_capturing_warns(
    yaml: &str,
) -> (Result<meow_config::Config, anyhow::Error>, Vec<String>) {
    let cap = CapWriter::new();
    let cap_clone = cap.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(cap)
        .with_ansi(false)
        .with_level(true)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    let result = load_config_from_str(yaml).await;
    drop(_guard);
    (result, cap_clone.captured())
}

// ─── Happy paths ─────────────────────────────────────────────────────────

#[tokio::test]
async fn wg_listener_full_fields_parse() {
    let peers = format!(
        "      - public-key: \"{PEER_PUB}\"\n        preshared-key: \"{PSK}\"\n        allowed-ips: [10.0.0.0/8, \"fd00::/8\"]\n        name: laptop\n        reserved: [13, 53, 133]\n      - public-key: \"{PEER_PUB2}\"\n        allowed-ips: [192.168.0.0/24]\n"
    );
    let yaml = wg_yaml(
        "    mtu: 1500\n    udp: false\n    udp-timeout: 120\n    max-connections: 64\n",
        &peers,
    );
    let config = load_config_from_str(&yaml).await.unwrap();
    let nl = &config.listeners.named[0];
    assert_eq!(nl.name, "wg-in");
    assert_eq!(nl.listen, "127.0.0.1");
    assert_eq!(nl.port, 0);
    assert_eq!(nl.max_connections, 64);
    let ListenerSpec::WireGuard(cfg) = &nl.spec else {
        panic!("expected WireGuard spec, got {:?}", nl.spec);
    };
    assert_eq!(nl.spec.type_name(), "wireguard");
    assert_eq!(nl.spec.to_string(), "wireguard");
    assert_eq!(cfg.mtu, 1500);
    assert!(!cfg.udp);
    assert_eq!(cfg.udp_timeout, std::time::Duration::from_secs(120));
    assert_eq!(cfg.peers.len(), 2);

    let p0 = &cfg.peers[0];
    assert_ne!(p0.public_key, [0u8; 32]);
    assert_eq!(p0.preshared_key.map(|k| k.len()), Some(32));
    assert_eq!(p0.allowed_ips.len(), 2);
    assert_eq!(p0.name.as_str(), "laptop");
    assert_eq!(p0.reserved, Some([13, 53, 133]));

    let p1 = &cfg.peers[1];
    assert_eq!(p1.preshared_key, None);
    assert_eq!(p1.name.as_str(), "peer-1", "unnamed peer gets peer-<index>");
    assert_eq!(p1.reserved, None);
}

#[tokio::test]
async fn wg_listener_minimal_defaults() {
    let cfg = build_wg(&minimal_yaml()).await;
    assert_eq!(cfg.mtu, 1420, "default mtu");
    assert!(cfg.udp, "default udp on");
    assert_eq!(cfg.udp_timeout, std::time::Duration::from_secs(60));
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].name.as_str(), "peer-0");
    assert_eq!(cfg.peers[0].preshared_key, None);
    assert_eq!(cfg.peers[0].reserved, None);
    assert_eq!(cfg.peers[0].allowed_ips.len(), 1);
}

/// An absent `listen` defaults to `0.0.0.0` for `type: wireguard` (spec
/// §2.1: a responder accepts peers from the network) — deliberately not
/// the shared `default_bind` convention other listener types use.
#[tokio::test]
async fn wg_listener_absent_listen_defaults_wildcard() {
    let yaml = minimal_yaml().replace("    listen: 127.0.0.1:0\n", "");
    let config = load_config_from_str(&yaml).await.unwrap();
    assert_eq!(config.listeners.named[0].listen, "0.0.0.0");
    assert_eq!(config.listeners.named[0].port, 0);
}

#[tokio::test]
async fn wg_listener_mtu_bounds() {
    for (mtu, ok) in [
        (639u16, false),
        (640, true),
        (1420, true),
        (9000, true),
        (9001, false),
    ] {
        let yaml = wg_yaml(&format!("    mtu: {mtu}\n"), &peer(""));
        match (load_config_from_str(&yaml).await, ok) {
            (Ok(_), true) => {}
            (Err(e), false) => assert!(format!("{e:#}").contains("640..=9000"), "{e:#}"),
            (Ok(_), false) => panic!("mtu {mtu} must be rejected"),
            (Err(e), true) => panic!("mtu {mtu} must parse: {e:#}"),
        }
    }
}

#[tokio::test]
async fn wg_reserved_accepts_list_and_base64() {
    for (form, expected) in [
        ("[13, 53, 133]", Some([13u8, 53, 133])),
        ("\"DTWF\"", Some([13u8, 53, 133])),
    ] {
        let p = peer(&format!("        reserved: {form}\n"));
        let cfg = build_wg(&wg_yaml("", &p)).await;
        assert_eq!(cfg.peers[0].reserved, expected, "form {form}");
    }
}

#[tokio::test]
async fn wg_reserved_wrong_shape_errors() {
    for (form, needle) in [
        ("[1, 2]", "exactly 3 bytes"),
        ("\"*bad*\"", "3-byte list or base64"),
        ("5", "3-byte list or base64"),
        // `QUJDRA==` decodes to 4 bytes — fails the 3-byte rule.
        ("\"QUJDRA==\"", "exactly 3 bytes"),
    ] {
        let p = peer(&format!("        reserved: {form}\n"));
        let err = err_of(&wg_yaml("", &p)).await;
        assert!(
            err.contains("reserved") && err.contains(needle),
            "{form}: {err}"
        );
    }
}

#[tokio::test]
async fn wg_preshared_key_parses_and_validates() {
    let p = peer(&format!("        preshared-key: \"{PSK}\"\n"));
    let cfg = build_wg(&wg_yaml("", &p)).await;
    assert_eq!(cfg.peers[0].preshared_key.map(|k| k.len()), Some(32));

    let p = peer("        preshared-key: \"!!!\"\n");
    let err = err_of(&wg_yaml("", &p)).await;
    assert!(
        err.contains("preshared-key") && err.contains("base64"),
        "{err}"
    );

    let p = peer(&format!("        preshared-key: \"{SHORT_B64}\"\n"));
    let err = err_of(&wg_yaml("", &p)).await;
    assert!(err.contains("exactly 32 bytes"), "{err}");
}

#[tokio::test]
async fn wg_max_connections_and_bind_conflict() {
    let yaml = wg_yaml("    max-connections: 7\n", &peer(""));
    let config = load_config_from_str(&yaml).await.unwrap();
    assert_eq!(config.listeners.named[0].max_connections, 7);
    // `listen` port vs `port` key conflict rides the shared
    // `resolve_listener_bind` rule — a WG listener gets no exemption.
    let yaml = format!(
        "listeners:\n  - name: wg-in\n    type: wireguard\n    listen: 127.0.0.1:51820\n    port: 51821\n    private-key: \"{LISTENER_PRIV}\"\n    peers:\n{}",
        peer("")
    );
    let err = err_of(&yaml).await;
    assert!(err.contains("conflicts"), "{err}");
}

/// A present-but-empty peer `name` is the same "no value" as an absent
/// one — the `peer-<index>` auto-label applies (the key helpers filter
/// empty strings the same way).
#[tokio::test]
async fn wg_peer_empty_name_falls_back_to_index() {
    let p = peer("        name: \"\"\n");
    let cfg = build_wg(&wg_yaml("", &p)).await;
    assert_eq!(cfg.peers[0].name.as_str(), "peer-0");
}

// ─── Hard errors ─────────────────────────────────────────────────────────

#[tokio::test]
async fn wg_missing_private_key_errors() {
    let yaml = format!(
        "listeners:\n  - name: wg-in\n    type: wireguard\n    listen: 127.0.0.1:0\n    peers:\n{}",
        peer("")
    );
    let err = err_of(&yaml).await;
    assert!(err.contains("private-key"), "{err}");
}

/// `private-key: ""` is present-but-empty, a different defect than an
/// absent key — the error must not call it "missing".
#[tokio::test]
async fn wg_empty_private_key_errors() {
    let yaml = minimal_yaml().replace(LISTENER_PRIV, "");
    let err = err_of(&yaml).await;
    assert!(err.contains("private-key"), "{err}");
    assert!(err.contains("empty"), "{err}");
    assert!(!err.contains("missing"), "{err}");
}

#[tokio::test]
async fn wg_bad_private_key_errors() {
    for (bad, needle) in [
        ("!!!not-base64!!!", "base64"),
        (SHORT_B64, "exactly 32 bytes"),
    ] {
        let yaml = minimal_yaml().replace(LISTENER_PRIV, bad);
        let err = err_of(&yaml).await;
        assert!(
            err.contains("private-key") && err.contains(needle),
            "{bad}: {err}"
        );
    }
}

#[tokio::test]
async fn wg_all_zero_private_key_errors() {
    let yaml = minimal_yaml().replace(LISTENER_PRIV, ZERO_KEY);
    let err = err_of(&yaml).await;
    assert!(err.contains("all-zero"), "{err}");
}

#[tokio::test]
async fn wg_missing_peers_errors() {
    let yaml = format!(
        "listeners:\n  - name: wg-in\n    type: wireguard\n    listen: 127.0.0.1:0\n    private-key: \"{LISTENER_PRIV}\"\n"
    );
    let err = err_of(&yaml).await;
    assert!(err.contains("peers"), "{err}");
}

#[tokio::test]
async fn wg_empty_peers_errors() {
    let yaml = format!(
        "listeners:\n  - name: wg-in\n    type: wireguard\n    listen: 127.0.0.1:0\n    private-key: \"{LISTENER_PRIV}\"\n    peers: []\n"
    );
    let err = err_of(&yaml).await;
    assert!(err.contains("peers"), "{err}");
}

#[tokio::test]
async fn wg_peer_missing_public_key_errors() {
    let p = "      - allowed-ips: [10.0.0.0/8]\n";
    let err = err_of(&wg_yaml("", p)).await;
    assert!(err.contains("public-key"), "{err}");
}

#[tokio::test]
async fn wg_peer_bad_public_key_errors() {
    let p = "      - public-key: \"not-base64\"\n        allowed-ips: [10.0.0.0/8]\n";
    let err = err_of(&wg_yaml("", p)).await;
    assert!(
        err.contains("public-key") && err.contains("base64"),
        "{err}"
    );
}

#[tokio::test]
async fn wg_duplicate_peer_public_key_errors() {
    let p = format!("{}{}", peer(""), peer(""));
    let err = err_of(&wg_yaml("", &p)).await;
    assert!(err.contains("duplicates"), "{err}");
}

#[tokio::test]
async fn wg_allowed_ips_required() {
    // Missing entirely.
    let p = format!("      - public-key: \"{PEER_PUB}\"\n");
    let err = err_of(&wg_yaml("", &p)).await;
    assert!(err.contains("allowed-ips"), "{err}");
    // Empty array is a hard error — the inbound ACL must be explicit
    // (deliberately unlike the outbound's empty-means-open default).
    let p = format!("      - public-key: \"{PEER_PUB}\"\n        allowed-ips: []\n");
    let err = err_of(&wg_yaml("", &p)).await;
    assert!(
        err.contains("allowed-ips") && err.contains("empty"),
        "{err}"
    );
    // Non-CIDR entry.
    let p = format!("      - public-key: \"{PEER_PUB}\"\n        allowed-ips: [not-a-cidr]\n");
    let err = err_of(&wg_yaml("", &p)).await;
    assert!(err.contains("not a valid CIDR"), "{err}");
}

#[tokio::test]
async fn wg_udp_timeout_zero_errors() {
    let yaml = wg_yaml("    udp-timeout: 0\n", &peer(""));
    let err = err_of(&yaml).await;
    assert!(err.contains("udp-timeout"), "{err}");
}

/// A peer `public-key` equal to the listener's own derived public key is
/// self-peering — rejected at config time when `wireguard` is compiled.
#[cfg(feature = "wireguard")]
#[tokio::test]
async fn wg_peer_public_key_equal_own_errors() {
    let p = format!("      - public-key: \"{LISTENER_PUB}\"\n        allowed-ips: [10.0.0.0/8]\n");
    let err = err_of(&wg_yaml("", &p)).await;
    assert!(err.contains("own public key"), "{err}");
}

/// Same input on builds without the `wireguard` feature: the config-time
/// check is compiled out (no x25519 in meow-config's deps) and the
/// listener startup path re-checks — pin the deferred semantics.
#[cfg(not(feature = "wireguard"))]
#[tokio::test]
async fn wg_peer_public_key_equal_own_defers_to_startup() {
    let p = format!("      - public-key: \"{LISTENER_PUB}\"\n        allowed-ips: [10.0.0.0/8]\n");
    let cfg = build_wg(&wg_yaml("", &p)).await;
    assert_eq!(cfg.peers.len(), 1);
}

// ─── Warn-and-ignore ─────────────────────────────────────────────────────

#[tokio::test]
async fn wg_unknown_and_foreign_keys_warn_not_error() {
    let p = peer("        pre-shared-key: \"AAAA\"\n");
    let yaml = wg_yaml("    cipher: aes-128-gcm\n    frobnicate: true\n", &p);
    let (result, lines) = load_capturing_warns(&yaml).await;
    result.unwrap_or_else(|e| panic!("unknown keys must warn, not error: {e:#}"));
    for needle in [
        "frobnicate",
        "cipher",
        "pre-shared-key",
        "not a known `type: wireguard` field",
        "not a known wireguard peer field",
    ] {
        assert!(
            lines.iter().any(|l| l.contains(needle)),
            "missing warn containing '{needle}': {lines:?}"
        );
    }
}

/// `udp: false` + `udp-timeout: N` is the same asymmetric misuse the
/// tproxy arm diagnoses — warn, don't silently consume.
#[tokio::test]
async fn wg_udp_timeout_with_udp_disabled_warns() {
    let yaml = wg_yaml("    udp: false\n    udp-timeout: 120\n", &peer(""));
    let (result, lines) = load_capturing_warns(&yaml).await;
    result.unwrap_or_else(|e| panic!("must warn, not error: {e:#}"));
    assert!(
        lines
            .iter()
            .any(|l| l.contains("udp-timeout") && l.contains("has no effect unless `udp: true`")),
        "missing udp-timeout warn: {lines:?}"
    );
    // Without `udp: false` the same timeout is consumed silently.
    let (result, lines) = load_capturing_warns(&wg_yaml("    udp-timeout: 120\n", &peer(""))).await;
    result.unwrap();
    assert!(
        !lines.iter().any(|l| l.contains("udp-timeout")),
        "no warn expected with udp enabled: {lines:?}"
    );
}

#[tokio::test]
async fn wg_only_fields_on_other_types_warn() {
    let yaml = format!(
        "listeners:\n  - name: m\n    type: mixed\n    listen: 127.0.0.1:0\n    private-key: \"{LISTENER_PRIV}\"\n    mtu: 1400\n"
    );
    let (result, lines) = load_capturing_warns(&yaml).await;
    result.unwrap();
    for needle in ["private-key", "mtu", "only meaningful on `type: wireguard`"] {
        assert!(
            lines.iter().any(|l| l.contains(needle)),
            "missing warn containing '{needle}': {lines:?}"
        );
    }
}

// ─── Debug redaction ─────────────────────────────────────────────────────

#[tokio::test]
async fn wg_debug_redacts_key_material() {
    let p = format!(
        "      - public-key: \"{PEER_PUB}\"\n        preshared-key: \"{PSK}\"\n        allowed-ips: [10.0.0.0/8]\n"
    );
    let cfg = build_wg(&wg_yaml("", &p)).await;
    let dbg = format!("{cfg:?}");
    // The stored forms are byte arrays — assert none of the private key's
    // or PSK's byte triplets leak, and the redaction marker is present.
    for needle in ["119, 7, 109", "74, 181, 107"] {
        assert!(!dbg.contains(needle), "key bytes leaked into Debug: {dbg}");
    }
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
    // public_key is deliberately NOT redacted (safe to log, needed for
    // diagnosis) — first bytes of PEER_PUB are 0xde 0x9e 0xdb.
    assert!(dbg.contains("222, 158, 219"), "{dbg}");
    // The base64 spelling never appears either (keys are stored decoded).
    assert!(!dbg.contains(LISTENER_PRIV) && !dbg.contains(PSK));
}

// ─── Serde / persisted-form round-trip ───────────────────────────────────

#[tokio::test]
async fn wg_spec_serde_tag_and_roundtrip() {
    let cfg = build_wg(&minimal_yaml()).await;
    let spec = ListenerSpec::WireGuard(cfg);
    let v = serde_json::to_value(&spec).unwrap();
    assert!(v.get("wireguard").is_some(), "lowercase serde tag: {v}");
    let back: ListenerSpec = serde_json::from_value(v).unwrap();
    assert_eq!(back, spec);
}
