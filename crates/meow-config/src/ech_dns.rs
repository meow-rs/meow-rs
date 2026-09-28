//! DNS-sourced ECH config lookup and pre-resolution pass.
//!
//! Resolves the wire-format `ECHConfigList` from an HTTPS (RR type 65) record
//! using the system nameservers (`/etc/resolv.conf` on Unix, a small built-in
//! fallback list on Windows).  Queries go through the internal `meow-dns`
//! client so socket creation can be intercepted by host integrations
//! (e.g. Android `protect()`).
//!
//! # Why not the in-process resolver?
//!
//! `meow-dns::Resolver` is built *from* the parsed config, so at parse time
//! it does not yet exist. We bootstrap with the system nameservers instead.
//!
//! # Why a separate pre-resolution pass?
//!
//! `parse_proxy` is sync and called from many places (including sync API
//! reload paths and #[test] unit tests). Pushing async DNS into it would
//! force a wide cascade. Instead, callers in async contexts run
//! [`preresolve_ech`] over the proxy YAML map *before* parsing — it walks
//! every proxy with `ech-opts: { enable: true }` and no inline `config:`,
//! does the HTTPS lookup, and writes the result back into the map as
//! base64. The downstream sync parser then sees a fully inline config.
//!
//! upstream: `component/ech/dns.go::QueryECHConfigList`
use base64::Engine;
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::{RData, RecordType};
use meow_dns::DnsClient;
use serde_yaml::Value;
use std::collections::HashMap;
#[cfg(unix)]
use std::net::SocketAddrV6;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Public DoH fallback used when no system nameserver answers an HTTPS RR
/// query. Many ISP/captive recursive resolvers refuse or strip RR type 65;
/// Cloudflare's resolver serves it reliably.
const DOH_FALLBACK_HOST: &str = "cloudflare-dns.com";
const DOH_FALLBACK_PATH: &str = "/dns-query";
/// Bootstrap A records for `cloudflare-dns.com`. Hard-coded so the DoH client
/// has somewhere to send the first packet without bootstrapping its own
/// resolver. If both fail, ECH lookup silently falls back to plain TLS.
const DOH_FALLBACK_IPS: &[IpAddr] = &[
    IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 1)),
];

/// Parse a resolv.conf-style nameserver token into a `SocketAddr` on port 53,
/// honouring an optional IPv6 zone identifier (`fe80::1%en0`). Rust's
/// `IpAddr::FromStr` rejects the `%zone` suffix outright, so we strip it and
/// resolve it through `if_nametoindex(3)` to populate `SocketAddrV6::scope_id`.
#[cfg(unix)]
fn parse_nameserver_token(token: &str) -> Option<SocketAddr> {
    // IPv6 addresses can carry a zone-id (`%en0`) — strip it before parsing
    // and feed it into the resulting SocketAddrV6 as a numeric scope_id.
    let (addr_str, zone) = match token.split_once('%') {
        Some((addr, z)) => (addr, Some(z)),
        None => (token, None),
    };
    let ip: IpAddr = addr_str.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => Some(SocketAddr::new(IpAddr::V4(v4), 53)),
        IpAddr::V6(v6) => {
            let scope = zone.map_or(0, zone_to_scope_id);
            Some(SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, scope)))
        }
    }
}

/// Resolve a textual zone identifier (interface name like `en0`, or a
/// numeric string like `4`) to a `scope_id`. Returns `0` on lookup failure,
/// which behaves the same as no scope from the kernel's perspective.
#[cfg(unix)]
fn zone_to_scope_id(zone: &str) -> u32 {
    if let Ok(n) = zone.parse::<u32>() {
        return n;
    }
    let Ok(c_name) = std::ffi::CString::new(zone) else {
        return 0;
    };
    // SAFETY: `if_nametoindex` reads the NUL-terminated string and returns
    // an index (or 0 on error); no aliasing or lifetime requirements.
    unsafe { libc::if_nametoindex(c_name.as_ptr()) }
}

/// `_ = Ipv6Addr` keeps the import live on non-unix builds without
/// triggering `unused_imports`. The IPv6 path itself only runs after a
/// successful parse.
const _: fn() = || {
    let _: Ipv6Addr = Ipv6Addr::UNSPECIFIED;
};

/// Read the platform's configured recursive resolvers.
///
/// Unix: parse `/etc/resolv.conf` `nameserver` lines.  Other platforms (or a
/// missing / unreadable resolv.conf) fall back to a short list of well-known
/// public resolvers so ECH lookups still succeed in unconfigured environments.
async fn system_nameservers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        if let Ok(contents) = tokio::fs::read_to_string("/etc/resolv.conf").await {
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                    continue;
                }
                let Some(rest) = line.strip_prefix("nameserver") else {
                    continue;
                };
                let token = rest.split_whitespace().next().unwrap_or("");
                if let Some(addr) = parse_nameserver_token(token) {
                    out.push(addr);
                }
            }
        }
    }
    if out.is_empty() {
        // Fallback: well-known public resolvers.
        out.push(SocketAddr::from(([1, 1, 1, 1], 53)));
        out.push(SocketAddr::from(([8, 8, 8, 8], 53)));
    }
    out
}

pub(crate) async fn fetch_ech_from_dns(name: &str) -> Result<Vec<u8>, String> {
    let nameservers = system_nameservers().await;
    let mut clients: Vec<Arc<DnsClient>> = nameservers
        .iter()
        .map(|addr| Arc::new(DnsClient::udp(*addr).with_timeout(Duration::from_secs(5))))
        .collect();

    // DoH fallback: many recursive resolvers refuse/strip HTTPS RR (type 65),
    // so layer a public DoH endpoint after the system-NS attempts. Without
    // this, ECH bootstrap silently falls back to plain TLS on restrictive
    // networks.
    for ip in DOH_FALLBACK_IPS {
        clients.push(Arc::new(
            DnsClient::doh(
                SocketAddr::new(*ip, 443),
                DOH_FALLBACK_HOST,
                DOH_FALLBACK_PATH,
            )
            .with_timeout(Duration::from_secs(5)),
        ));
    }

    let mut last_err: Option<String> = None;
    let mut response = None;
    for c in &clients {
        match c.query(name, RecordType::HTTPS).await {
            Ok(msg) => {
                response = Some(msg);
                break;
            }
            Err(e) => last_err = Some(format!("{e}")),
        }
    }
    let msg = response.ok_or_else(|| {
        format!(
            "ech-dns: HTTPS lookup for {name} failed via all nameservers (system + DoH {DOH_FALLBACK_HOST}): {}",
            last_err.unwrap_or_else(|| "no nameservers".to_string())
        )
    })?;

    for record in &msg.answers {
        let svcb = match &record.data {
            RData::HTTPS(https) => &https.0,
            _ => continue,
        };
        for (_, value) in &svcb.svc_params {
            if let SvcParamValue::EchConfigList(list) = value {
                if !list.0.is_empty() {
                    return Ok(list.0.clone());
                }
            }
        }
    }

    Err(format!(
        "ech-dns: no ECH config (SvcParam key 5) in HTTPS record for {name}"
    ))
}

/// Walk a slice of proxy YAML maps and pre-resolve any DNS-sourced ECH
/// configs in-place. Proxies with `ech-opts: { enable: true }` and no
/// inline `config:` get a HTTPS-record lookup (using `query-server-name`
/// if present, else `server`); on success, the base64 of the wire-format
/// `ECHConfigList` is written into `ech-opts.config`.
///
/// Failures are logged at warn level and leave the map unchanged — the
/// downstream parser will then see `enable: true` with no `config:` and
/// silently skip ECH for that proxy (matches Go upstream behaviour:
/// "ECH lookup failed, proceed without ECH").
///
/// `strict` (top-level `strict: true`, issue #533): `enable: true` with no
/// `config:`, no `query-server-name:`, and no `server:` to query is a
/// config *defect* (ECH can never engage) and returns `Err` — DNS lookup
/// failures stay lenient in both modes since they are transient.
///
/// The defect check alone (no network I/O) is [`check_ech_defects`] —
/// runtime mutation paths already holding the config-mutation lane call
/// that instead of this function so no DNS lookup serializes other
/// commits (issue #533 review).
pub async fn preresolve_ech(
    proxies: &mut [HashMap<String, Value>],
    strict: bool,
) -> Result<(), String> {
    check_ech_defects(proxies, strict)?;
    if crate::is_offline_validate() {
        return Ok(());
    }
    for proxy in proxies {
        let proxy_name = proxy
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let server = proxy
            .get("server")
            .and_then(|v| v.as_str())
            .map(String::from);

        let Some(ech_opts) = proxy.get_mut("ech-opts") else {
            continue;
        };
        let Some(ech_map) = ech_opts.as_mapping_mut() else {
            continue;
        };

        let enabled = ech_map
            .get(Value::String("enable".into()))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        if ech_map
            .get(Value::String("config".into()))
            .and_then(|v| v.as_str())
            .is_some()
        {
            continue;
        }

        let query_name = ech_map
            .get(Value::String("query-server-name".into()))
            .and_then(|v| v.as_str())
            .map(String::from)
            .or(server);
        // No query source: `check_ech_defects` above already warned
        // (lenient) or returned Err (strict), so just skip the lookup.
        let Some(query_name) = query_name else {
            continue;
        };

        match fetch_ech_from_dns(&query_name).await {
            Ok(bytes) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                tracing::info!(
                    proxy = %proxy_name,
                    query = %query_name,
                    len = bytes.len(),
                    "ech-opts: fetched ECH config from DNS HTTPS record"
                );
                ech_map.insert(Value::String("config".into()), Value::String(b64));
            }
            Err(e) => {
                tracing::warn!(
                    proxy = %proxy_name,
                    query = %query_name,
                    error = %e,
                    "ech-opts: DNS lookup failed; continuing without ECH"
                );
            }
        }
    }
    Ok(())
}

/// The pure-defect half of [`preresolve_ech`], with no network I/O:
/// `ech-opts.enable: true` without `config:` and without any name to query
/// (`query-server-name:` or `server:`) is a config defect that can never
/// engage ECH — under `strict` it returns `Err`; leniently it warns.
/// Runtime paths holding the config-mutation lane run this instead of the
/// full preresolve so no DNS lookup serializes other commits (issue #533
/// review); writers are expected to have preresolved before storing.
pub fn check_ech_defects(proxies: &[HashMap<String, Value>], strict: bool) -> Result<(), String> {
    for proxy in proxies {
        let proxy_name = proxy
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let server = proxy.get("server").and_then(|v| v.as_str());
        let has_query_source = server.is_some()
            || proxy
                .get("ech-opts")
                .and_then(|v| v.as_mapping())
                .is_some_and(|m| {
                    m.get(Value::String("query-server-name".into()))
                        .and_then(|v| v.as_str())
                        .is_some()
                });
        let enabled_without_config = proxy
            .get("ech-opts")
            .and_then(|v| v.as_mapping())
            .is_some_and(|m| {
                m.get(Value::String("enable".into()))
                    .and_then(serde_yaml::Value::as_bool)
                    .unwrap_or(false)
                    && m.get(Value::String("config".into()))
                        .and_then(|v| v.as_str())
                        .is_none()
            });
        if !enabled_without_config {
            continue;
        }
        if !has_query_source {
            let msg = format!(
                "proxy '{proxy_name}': ech-opts.enable=true with no `config:`, no \
                 `query-server-name:`, and no `server:` to fall back on"
            );
            if strict {
                return Err(msg);
            }
            tracing::warn!(proxy = %proxy_name, "{msg}; skipping ECH");
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_nameserver() {
        let got = parse_nameserver_token("8.8.8.8").unwrap();
        assert_eq!(got, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_ipv6_nameserver_without_zone() {
        let got = parse_nameserver_token("2001:4860:4860::8888").unwrap();
        match got {
            SocketAddr::V6(s) => {
                assert_eq!(s.port(), 53);
                assert_eq!(s.scope_id(), 0);
            }
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn ipv6_zone_id_does_not_get_rejected() {
        // The previous code returned None here because `IpAddr::FromStr`
        // rejects the `%en0` suffix. The fix is that we strip the zone and
        // resolve it separately.
        let got = parse_nameserver_token("fe80::1%en0");
        assert!(got.is_some(), "fe80::1%en0 must parse, not silently drop");
        match got.unwrap() {
            SocketAddr::V6(s) => {
                assert_eq!(s.port(), 53);
                // scope_id may be 0 if `en0` doesn't exist in this test
                // environment — what matters is that the line was parsed
                // rather than silently dropped.
            }
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn ipv6_numeric_zone_id_parses() {
        let got = parse_nameserver_token("fe80::1%4").unwrap();
        match got {
            SocketAddr::V6(s) => assert_eq!(s.scope_id(), 4),
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn garbage_token_returns_none() {
        assert!(parse_nameserver_token("not-an-ip").is_none());
        assert!(parse_nameserver_token("").is_none());
    }
}
