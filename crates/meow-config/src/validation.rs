//! Warn-only unknown-key reporting (issue #974, ADR-0002 Class B).
//!
//! Every surface that silently dropped unrecognized YAML keys gets a
//! `#[serde(flatten)] extra` capture on its raw struct (or a known-key
//! inventory for the free-form `proxies:` map), and the emits here turn
//! those captures into one warning per category — never an error, so a
//! verbatim mihomo config keeps loading.

use std::collections::{BTreeMap, HashMap};
use tracing::warn;

/// mihomo keys this build deliberately does not implement, mapped to
/// (tracking issue, why). Anything else unknown is `Unrecognized`; any
/// `brutal-*` key is Unsupported without a registry entry (open-ended
/// experimental surface, no spec).
const UNSUPPORTED_KEYS: &[(&str, Option<u32>, &str)] = &[
    ("brutal-delay", None, "experimental, no spec"),
    ("brutal-opts", None, "experimental, no spec"),
    (
        "geox-update-interval",
        None,
        "superseded by geodata.auto-update-interval",
    ),
    (
        "external-controller-routing-mark",
        Some(974),
        "controller listener SO_MARK not implemented",
    ),
    ("tunnels", Some(974), "inbound tunnels not implemented"),
    ("udp-over-tcp", None, "UDP-over-TCP not implemented"),
    ("udp-over-tcp-version", None, "UDP-over-TCP not implemented"),
    (
        "timeout",
        None,
        "per-group/per-node timeout not modeled \
         (sniffer, nftset, provider health-check honor it)",
    ),
    ("max-failed-times", None, "group probe tuning not modeled"),
    ("disable-udp", None, "per-group UDP disable not modeled"),
];

/// Keys an operator plausibly places on the wrong surface — mapped to the
/// surface that actually honors them. Checked only against keys already
/// found unknown at the emitting surface, so a surface where the key is
/// legitimate never reaches this table.
const MISPLACED_KEYS: &[(&str, &str)] = &[
    ("firewall", "a listeners: entry (type: tproxy)"),
    (
        "udp",
        "a listeners: (tproxy/shadowsocks/wireguard) entry, \
         or a UDP-capable proxies: node",
    ),
    (
        "udp-timeout",
        "a listeners: (tproxy/wireguard) or tun: entry",
    ),
    ("tfo", "a proxies: entry (per-node dialer option)"),
    ("mptcp", "a proxies: entry (per-node dialer option)"),
    ("ip-version", "a proxies: entry (per-node dialer option)"),
    (
        "routing-mark",
        "the top level or a proxies: entry (per-node dialer option)",
    ),
    (
        "interface-name",
        "the top level or a proxies: entry (per-node dialer option)",
    ),
    (
        "dialer-proxy",
        "a proxies: entry or a proxy-providers: entry",
    ),
    (
        "global-client-fingerprint",
        "the top-level config (use 'client-fingerprint' on a proxies: entry)",
    ),
    ("global-ua", "the top-level config"),
    (
        "keep-alive-idle",
        "the top-level config (outbound-dial keepalive)",
    ),
    (
        "keep-alive-interval",
        "the top-level config (outbound-dial keepalive)",
    ),
    (
        "disable-keep-alive",
        "the top-level config (outbound-dial keepalive)",
    ),
    (
        "statistic",
        "a proxies: entry's smux: block (and is ignored there: \
         carrier-level traffic accounting is not modeled)",
    ),
    (
        "max-connections",
        "the top-level config or a trusttunnel: node (a smux: block \
         accepts it on trojan/vless/ss/vmess nodes)",
    ),
    (
        "min-streams",
        "a trusttunnel: node or a proxies: entry's smux: block",
    ),
    (
        "max-streams",
        "a trusttunnel: node or a proxies: entry's smux: block",
    ),
];

/// Frequent misspellings of a real mihomo key — the hint renders inline
/// in the unrecognized-keys line, verbatim after "not recognized; ".
const NEAR_MISS_KEYS: &[(&str, &str)] = &[
    ("test-timeout", "mihomo uses 'timeout' (not modeled here)"),
    ("skip-cert-verfiy", "mihomo uses 'skip-cert-verify'"),
];

enum KeyClass<'a> {
    Unrecognized,
    Unsupported {
        issue: Option<u32>,
        hint: &'static str,
    },
    Misplaced {
        correct_surface: &'a str,
    },
}

fn classify(key: &str) -> KeyClass<'static> {
    if let Some(&(_, issue, hint)) = UNSUPPORTED_KEYS.iter().find(|(k, _, _)| *k == key) {
        return KeyClass::Unsupported { issue, hint };
    }
    if key.starts_with("brutal-") {
        return KeyClass::Unsupported {
            issue: None,
            hint: "experimental, no spec",
        };
    }
    if let Some(&(_, correct)) = MISPLACED_KEYS.iter().find(|(k, _)| *k == key) {
        return KeyClass::Misplaced {
            correct_surface: correct,
        };
    }
    KeyClass::Unrecognized
}

/// Emit sorted, deduplicated warnings for `keys` reported against
/// `context` ("top-level config", "proxy 'x'", …). One aggregated line
/// per category: unsupported and misplaced keys get one line each (their
/// hints differ per key); unrecognized keys share one comma-joined line,
/// except a key with a near-miss spelling, which gets its own line so the
/// suggestion stays attached.
pub(crate) fn emit_unknown_keys_warn(context: &str, keys: &[String]) {
    if keys.is_empty() {
        return;
    }
    let mut sorted = keys.to_vec();
    sorted.sort();
    sorted.dedup();

    let mut unrecognized: Vec<&str> = Vec::new();
    for key in &sorted {
        match classify(key) {
            KeyClass::Unrecognized => {
                if let Some(hint) = NEAR_MISS_KEYS
                    .iter()
                    .find(|(m, _)| *m == key.as_str())
                    .map(|(_, h)| h)
                {
                    warn!("unknown keys in {context}: {key} (not recognized; {hint})");
                } else {
                    unrecognized.push(key.as_str());
                }
            }
            KeyClass::Unsupported { issue, hint } => {
                let issue_ref = issue.map_or(String::new(), |n| format!(" (issue #{n})"));
                warn!("unsupported key in {context}: {key}{issue_ref} — {hint}");
            }
            KeyClass::Misplaced { correct_surface } => {
                warn!("misplaced key in {context}: {key} (belongs on {correct_surface})");
            }
        }
    }
    if !unrecognized.is_empty() {
        warn!(
            "unknown keys in {context}: {} (not recognized; check spelling or see \
             https://github.com/madeye/meow-rs/issues/974)",
            unrecognized.join(", ")
        );
    }
}

/// Keys every `proxies:` leaf honors regardless of `type:` — the entry's
/// own identity plus the shared per-node dialer surface (issue #977) and
/// `dialer-proxy`, which the build consumes before leaf parse.
const COMMON_NODE_KEYS: &[&str] = &[
    "type",
    "name",
    "dialer-proxy",
    "routing-mark",
    "interface-name",
    "ip-version",
    "tfo",
    "mptcp",
];

const SS_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "password",
    "cipher",
    "udp",
    "plugin",
    "plugin-opts",
    "client-fingerprint",
    "smux",
    "mux",
];

const TROJAN_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "password",
    "sni",
    "skip-cert-verify",
    "udp",
    "smux",
    "mux",
];

const VLESS_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "uuid",
    "udp",
    "tls",
    "skip-cert-verify",
    "servername",
    "alpn",
    "network",
    "client-fingerprint",
    "reality-opts",
    "encryption",
    "flow",
    "ech-opts",
    "ws-opts",
    "grpc-opts",
    "h2-opts",
    "http-upgrade-opts",
    "xhttp-opts",
    "smux",
    "mux",
];

const HTTP_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "tls",
    "skip-cert-verify",
    "username",
    "password",
    "headers",
];

const SOCKS5_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "tls",
    "skip-cert-verify",
    "username",
    "password",
    "udp",
];

const DIRECT_NODE_KEYS: &[&str] = &["connect-timeout", "dns"];

/// `type: rematch` (issue #974) — a control outbound: no `server`/`port`,
/// no `udp` (the transition preempts the capability check, so `udp: false`
/// reads as an ignored unknown key), just the two re-entry targets.
const REMATCH_NODE_KEYS: &[&str] = &["target-rematch-name", "target-sub-rule"];

/// `type: dns` (issue #974) — an in-process resolver leaf with no
/// endpoint keys of its own: `server`/`port`/`udp` and the transport
/// family all read as ignored unknown keys.
const DNS_NODE_KEYS: &[&str] = &[];

const TRUSTTUNNEL_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "username",
    "password",
    "sni",
    "skip-cert-verify",
    "name-cert-verify",
    "client-fingerprint",
    "alpn",
    "udp",
    "quic",
    "max-connections",
    "min-streams",
    "max-streams",
    "platform",
    "app-name",
    "headers",
    "health-check",
    // Present keys get a named parse error, not a warn — listed so they
    // are not also flagged unrecognized on top of that error.
    "certificate",
    "private-key",
    "fingerprint",
    "cert-fingerprint",
    "reality-opts",
    "ech-opts",
    "curve-preferences",
    "ca",
    "ca-str",
    "bbr-profile",
    "bbr-opts",
    "congestion-controller",
    "cwnd",
];

const ANYTLS_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "password",
    "sni",
    "skip-cert-verify",
    "udp",
    "alpn",
    "fingerprint",
    "name-cert-verify",
    "client-fingerprint",
    // Rejected or warn-ignored by the adapter's own checks — consumed
    // keys, not unknown ones.
    "ech-opts",
    "certificate",
    "private-key",
    "shadow-tls-opts",
    "restls-opts",
    "jls-opts",
    "client-metadata",
    "idle-session-check-interval",
    "idle-session-timeout",
    "min-idle-session",
    "disable-reuse",
];

const HYSTERIA2_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "ports",
    "password",
    "sni",
    "skip-cert-verify",
    "udp",
    "up",
    "down",
    "obfs",
    "obfs-password",
    "obfs-min-packet-size",
    "obfs-max-packet-size",
    "hop-interval",
    "fingerprint",
    "fast-open",
    "alpn",
    "initial-stream-receive-window",
    "max-stream-receive-window",
    "initial-connection-receive-window",
    "max-connection-receive-window",
    "quic-connections",
    // Rejected by the adapter's own checks — see TRUSTTUNNEL_NODE_KEYS.
    "certificate",
    "private-key",
    "ech-opts",
    "realm-opts",
    "cwnd",
    "udp-mtu",
    "bbr-profile",
];

const WIREGUARD_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "private-key",
    "public-key",
    "pre-shared-key",
    "ip",
    "ipv6",
    "allowed-ips",
    "reserved",
    "mtu",
    "udp",
    "remote-dns-resolve",
    "persistent-keepalive",
    "dns",
    "ip-stack",
    // Hard parse error when present — see TRUSTTUNNEL_NODE_KEYS.
    "amnezia-wg-option",
];

const SNELL_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "psk",
    "udp",
    "reuse",
    "version",
    "obfs-opts",
    "mode",
];

const VMESS_NODE_KEYS: &[&str] = &[
    "server",
    "port",
    "uuid",
    "alterId",
    "cipher",
    "udp",
    "tls",
    "skip-cert-verify",
    "servername",
    "alpn",
    "network",
    "client-fingerprint",
    "ws-opts",
    "smux",
    "mux",
];

/// The known-key inventory for a `proxies:` entry's `type`, or `None`
/// when the type is unrecognized (the leaf parse reports that separately;
/// warning on every key would bury it).
fn known_node_keys(proxy_type: &str) -> Option<&'static [&'static str]> {
    let per_type: &[&str] = match proxy_type {
        "ss" => SS_NODE_KEYS,
        "trojan" => TROJAN_NODE_KEYS,
        "vless" => VLESS_NODE_KEYS,
        "http" => HTTP_NODE_KEYS,
        "socks5" => SOCKS5_NODE_KEYS,
        "direct" => DIRECT_NODE_KEYS,
        "rematch" => REMATCH_NODE_KEYS,
        "dns" => DNS_NODE_KEYS,
        "trusttunnel" => TRUSTTUNNEL_NODE_KEYS,
        "anytls" => ANYTLS_NODE_KEYS,
        "hysteria2" => HYSTERIA2_NODE_KEYS,
        "vmess" => VMESS_NODE_KEYS,
        "snell" => SNELL_NODE_KEYS,
        "wireguard" | "WireGuard" => WIREGUARD_NODE_KEYS,
        _ => return None,
    };
    Some(per_type)
}

/// Warn on `proxies:`/`proxy-provider` node keys outside the `type`'s
/// inventory. `provider` names the source for provider-expanded nodes
/// (issue #974 Q1); `None` marks a `proxies:` entry (which includes
/// subscription-contributed nodes — they merge into `raw.proxies`).
pub(crate) fn warn_unknown_node_keys(
    config: &HashMap<String, serde_json::Value>,
    provider: Option<&str>,
) {
    let Some(name) = config.get("name").and_then(|v| v.as_str()) else {
        // A nameless/mistyped node fails its parse with a named error;
        // flagging every key would bury that report.
        return;
    };
    let Some(known) = config
        .get("type")
        .and_then(|v| v.as_str())
        .and_then(known_node_keys)
    else {
        return;
    };
    let unknown: Vec<String> = config
        .keys()
        .filter(|k| !COMMON_NODE_KEYS.contains(&k.as_str()) && !known.contains(&k.as_str()))
        .cloned()
        .collect();
    let context = match provider {
        Some(p) => format!("proxy '{name}' (from provider '{p}')"),
        None => format!("proxy '{name}'"),
    };
    emit_unknown_keys_warn(&context, &unknown);
}

/// Emit the extra-map warnings for one section of a parsed config —
/// shared by `validate_and_warn` and the `listeners:` build loop (which
/// owns its own warn site for spec context). Only the keys matter, so
/// the map's value type is left generic.
pub(crate) fn warn_extra<T>(context: &str, extra: &BTreeMap<String, T>) {
    emit_unknown_keys_warn(context, &extra.keys().cloned().collect::<Vec<_>>());
}

/// The `store-fake-ip` spelling conflict — `profile` wins when the two
/// disagree. Emitted at the document-parse boundary (`parse_raw_yaml`)
/// rather than inside [`validate_and_warn`], because the admission it is
/// scoped to is the document itself: a startup runs two rebuild passes
/// and a `PUT` up to two more over the same raw, and per-pass emission
/// double-warned the operator (issue #974).
pub(crate) fn warn_store_fake_ip_alias(raw: &crate::raw::RawConfig) {
    if let (Some(pv), Some(dv)) = (
        raw.profile.as_ref().and_then(|p| p.store_fake_ip),
        raw.dns.as_ref().and_then(|d| d.store_fake_ip),
    ) {
        if pv != dv {
            warn!(
                "profile.store-fake-ip ({pv}) and dns.store-fake-ip ({dv}) disagree — \
                 the profile value wins"
            );
        }
    }
}

/// Warn on every key the typed schema dropped silently, across all
/// surfaces [`crate::raw::RawConfig`] models — called once per rebuild
/// pass so `-t` validation, startup, and `PUT`/`PATCH /configs` reloads
/// all emit (Class B: warn-only, never an error).
///
/// Deliberately silent surfaces:
/// - `listeners:`/`peers:` extras are warned where `build_named_listeners`
///   runs (it owns the per-type arms; `type: wireguard` entries and peers
///   keep their bespoke messages there).
/// - Key-spaces that are caller-chosen names rather than a fixed schema:
///   `hosts:`, `sub-rules:`, `nameserver-policy:`-style maps and the
///   `sniff:` protocol names.
/// - `proxy-providers[].override:` keys other than `dialer-proxy` already
///   warn at provider construction.
/// - `dns.response-rules[]` uses `deny_unknown_fields` — a hard error by
///   design, not a warn.
pub(crate) fn validate_and_warn(raw: &crate::raw::RawConfig) {
    // Top-level `certificate`/`private-key` are silently dead upstream —
    // mihomo reads them NESTED under `tls:` (issue #974). Warn as
    // misplaced with the canonical key names rather than lumping them
    // into the unrecognized list; never interpreted as an identity.
    let mut extra_keys: Vec<String> = raw.extra.keys().cloned().collect();
    for key in ["certificate", "private-key"] {
        if extra_keys.iter().any(|k| k == key) {
            extra_keys.retain(|k| k != key);
            warn!(
                "misplaced key in top-level config: {key} (mihomo reads it nested \
                 as tls.{key}; the top-level spelling is ignored)"
            );
        }
    }
    emit_unknown_keys_warn("top-level config", &extra_keys);

    // Controller CORS + TLS sections (issue #974): known keys are
    // implemented or warn-ignored below; anything else unknown warns
    // scoped to its own section.
    if let Some(cors) = &raw.external_controller_cors {
        warn_extra("external-controller-cors", &cors.extra);
    }
    if let Some(tls) = &raw.tls {
        warn_extra("tls", &tls.extra);
        // Parsed-but-unimplemented `tls:` members — warn-ignore this
        // batch, under `strict` too (Class B, ADR-0002).
        for (key, present) in [
            ("client-auth-type", tls.client_auth_type.is_some()),
            (
                "client-auth-certificates",
                tls.client_auth_certificates.is_some(),
            ),
            ("ech-key", tls.ech_key.is_some()),
            ("custom-certifactes", tls.custom_certifactes.is_some()),
        ] {
            if present {
                warn!("unsupported key in tls: {key} (issue #974) — parsed but not implemented; ignored");
            }
        }
    }
    // Platform listeners upstream only serves on one OS: warn-ignore the
    // configured key everywhere else, never a validation error.
    if !cfg!(windows)
        && raw
            .external_controller_pipe
            .as_deref()
            .is_some_and(|s| !s.is_empty())
    {
        warn!("external-controller-pipe is set but named pipes are only supported on Windows — ignored");
    }
    if !cfg!(unix)
        && raw
            .external_controller_unix
            .as_deref()
            .is_some_and(|s| !s.is_empty())
    {
        warn!("external-controller-unix is set but Unix-domain sockets are only supported on Unix — ignored");
    }

    // `global-client-fingerprint` names a uTLS profile; an unsupported
    // name degrades to the TLS backend's defaults on every inheriting
    // node — warn once per rebuild so the operator sees the effective
    // hello is unshaped (Class B, matching the per-node contract).
    if let Some(fp) =
        crate::proxy_parser::normalize_client_fingerprint(raw.global_client_fingerprint.as_deref())
    {
        if !meow_transport::tls::is_supported_fingerprint(&fp) {
            warn!(
                "global-client-fingerprint=\"{fp}\" is not a supported uTLS profile \
                 (expected chrome, firefox, safari, ios, android, edge, or random); \
                 nodes inheriting it will fall back to default TLS parameters"
            );
        }
    }

    if let Some(ntp) = &raw.ntp {
        warn_extra("ntp", &ntp.extra);
        // Always warn-and-ignore, even when disabled: the knob reads like
        // it writes the OS clock and meow never invokes one (issue #974).
        if ntp.write_to_system == Some(true) {
            warn!(
                "ntp.write-to-system: ignored — meow never writes the system clock;                  the offset adjusts VMess/REALITY protocol timestamps only"
            );
        }
    }
    if let Some(profile) = &raw.profile {
        warn_extra("profile", &profile.extra);
    }
    if let Some(dns) = &raw.dns {
        warn_extra("dns", &dns.extra);
        if let Some(ff) = &dns.fallback_filter {
            warn_extra("dns.fallback-filter", &ff.extra);
        }
        if let Some(nft) = &dns.nftset {
            warn_extra("dns.nftset", &nft.extra);
        }
    }
    if let Some(tun) = &raw.tun {
        warn_extra("tun", &tun.extra);
    }
    if let Some(sniffer) = &raw.sniffer {
        warn_extra("sniffer", &sniffer.extra);
        if let Some(sniff) = &sniffer.sniff {
            for (proto, sp) in sniff {
                warn_extra(&format!("sniffer.sniff.{proto}"), &sp.extra);
            }
        }
    }
    if let Some(geodata) = &raw.geodata {
        warn_extra("geodata", &geodata.extra);
        if let Some(url) = &geodata.url {
            warn_extra("geodata.url", &url.extra);
        }
    }
    // The geo selectors (`geodata-mode`, `geodata-loader`,
    // `geosite-matcher`, legacy `geoip-matcher`) warn on their effective
    // value — flat alias or nested — once per validation pass.
    crate::geodata::warn_geo_compat(raw);
    if let Some(geox) = &raw.geox_url {
        warn_extra("geox-url", &geox.extra);
    }
    if let Some(logbook) = &raw.logbook {
        warn_extra("logbook", &logbook.extra);
    }
    if let Some(ledger) = &raw.traffic_ledger {
        warn_extra("traffic-ledger", &ledger.extra);
    }
    for node in raw.proxies.as_deref().unwrap_or(&[]) {
        warn_unknown_node_keys(node, None);
    }
    for group in raw.proxy_groups.as_deref().unwrap_or(&[]) {
        warn_extra(&format!("proxy-group '{}'", group.name), &group.extra);
    }
    for (name, provider) in raw.proxy_providers.iter().flatten() {
        warn_extra(&format!("proxy-provider '{name}'"), &provider.extra);
        if let Some(hc) = &provider.health_check {
            warn_extra(&format!("proxy-provider '{name}' health-check"), &hc.extra);
        }
    }
    for (name, provider) in raw.rule_providers.iter().flatten() {
        warn_extra(&format!("rule-provider '{name}'"), &provider.extra);
    }
    for sub in raw.subscriptions.as_deref().unwrap_or(&[]) {
        warn_extra(&format!("subscription '{}'", sub.name), &sub.extra);
    }
}
