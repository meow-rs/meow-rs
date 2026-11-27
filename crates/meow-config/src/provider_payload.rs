//! Provider payloads that are not YAML: the share-link list.
//!
//! mihomo's provider parser falls back to `convert.ConvertsV2Ray` when the
//! body is not YAML: it base64-decodes the payload and reads a list of
//! share links (`ss://`, `vmess://`, `vless://`, `trojan://`,
//! `hysteria2://`, `anytls://`). Airports commonly serve that format
//! depending on the request's `User-Agent` — the same subscription URL
//! answers with YAML to a clash UA and with base64 links to `mihomo` — so
//! a kernel that only reads YAML silently ends up with an empty provider.
//!
//! This module owns the decoding and the per-scheme mapping into the same
//! node maps the YAML path produces, so the rest of the provider pipeline
//! (filters, override, strictness, dialer injection) is shared.

use base64::Engine as _;
use serde_json::{Map, Value};
use std::collections::HashMap;

/// Decoded payload text: base64 (padded or not, standard or URL-safe), or
/// the payload as written when it is already plain text.
///
/// A body that decodes to something without a scheme is not a share-link
/// list; returning it verbatim lets the caller fail with the same error a
/// plain non-YAML payload always produced.
fn decode_body(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.contains("://") {
        return trimmed.to_string();
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        let Ok(bytes) = engine.decode(trimmed) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        if text.contains("://") {
            return text;
        }
    }
    trimmed.to_string()
}

/// Parse a share-link payload into node maps.
///
/// `Err` means the payload carried no usable link at all — the caller keeps
/// the last-good provider generation, exactly as it does for a YAML parse
/// failure. Individual lines that fail (an unsupported scheme, a malformed
/// URL) are skipped with a warning: one broken line in a third-party feed
/// must not empty the whole provider.
pub(crate) fn parse_share_links(content: &str) -> Result<Vec<HashMap<String, Value>>, String> {
    let body = decode_body(content);
    let mut nodes = Vec::new();
    let mut skipped = 0usize;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || !line.contains("://") {
            continue;
        }
        match parse_link(line) {
            Ok(node) => nodes.push(node),
            Err(e) => {
                skipped = skipped.saturating_add(1);
                tracing::warn!(error = %e, "skipping an unparsable share link");
            }
        }
    }
    if nodes.is_empty() {
        return Err(format!(
            "no share link could be parsed ({skipped} line(s) rejected)"
        ));
    }
    Ok(nodes)
}

fn parse_link(line: &str) -> Result<HashMap<String, Value>, String> {
    let (scheme, rest) = line
        .split_once("://")
        .ok_or_else(|| "missing scheme separator".to_string())?;
    match scheme.to_ascii_lowercase().as_str() {
        "ss" => parse_ss(rest),
        "vmess" => parse_vmess(rest),
        "vless" => parse_vless(rest),
        "trojan" => parse_trojan(rest),
        "hysteria2" | "hy2" => parse_hysteria2(rest),
        "anytls" => parse_anytls(rest),
        other => Err(format!("scheme '{other}' is not supported")),
    }
}

// ── shared helpers ──────────────────────────────────────────────────────

/// Percent-decode `input` (RFC 3986). Invalid escapes stay literal.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Base64 (any alphabet, padded or not) to text.
fn base64_text(input: &str) -> Option<String> {
    let trimmed = input.trim();
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(trimmed) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }
    None
}

fn split_fragment(input: &str) -> (&str, Option<&str>) {
    match input.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment)),
        None => (input, None),
    }
}

fn split_query(input: &str) -> (&str, Option<&str>) {
    match input.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (input, None),
    }
}

fn query_map(query: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(query) = query else {
        return map;
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(
            percent_decode(key).to_ascii_lowercase(),
            percent_decode(value),
        );
    }
    map
}

/// Split `host:port`, honouring `[::1]:443`.
fn split_host_port(input: &str) -> Result<(String, u16), String> {
    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| format!("'{input}' has no port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("'{port}' is not a valid port"))?;
    Ok((host.to_string(), port))
}

fn node(kind: &str, name: &str, server: &str, port: u16) -> HashMap<String, Value> {
    let mut map = HashMap::new();
    map.insert("name".to_string(), Value::String(name.to_string()));
    map.insert("type".to_string(), Value::String(kind.to_string()));
    map.insert("server".to_string(), Value::String(server.to_string()));
    map.insert("port".to_string(), Value::from(port));
    map
}

fn display_name(fragment: Option<&str>, server: &str, port: u16) -> String {
    match fragment {
        Some(raw) => {
            let decoded = percent_decode(raw);
            if decoded.trim().is_empty() {
                format!("{server}:{port}")
            } else {
                decoded
            }
        }
        None => format!("{server}:{port}"),
    }
}

fn insert_str(map: &mut HashMap<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        map.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn insert_bool(map: &mut HashMap<String, Value>, key: &str, value: bool) {
    map.insert(key.to_string(), Value::Bool(value));
}

fn truthy(value: Option<&String>) -> bool {
    matches!(value.map(String::as_str), Some("1" | "true" | "yes" | "on"))
}

// ── ss ──────────────────────────────────────────────────────────────────

/// `ss://` in SIP002 form (`ss://base64(method:password)@host:port`) or the
/// legacy fully-encoded form (`ss://base64(method:password@host:port)`).
fn parse_ss(rest: &str) -> Result<HashMap<String, Value>, String> {
    let (body, fragment) = split_fragment(rest);
    let (body, query) = split_query(body);
    let params = query_map(query);

    let (credentials, hostport) = match body.rsplit_once('@') {
        Some((credentials, hostport)) => (percent_decode(credentials), hostport.to_string()),
        None => {
            let decoded = base64_text(body)
                .ok_or_else(|| "ss link is neither userinfo@host:port nor base64".to_string())?;
            let (credentials, hostport) = decoded
                .rsplit_once('@')
                .ok_or_else(|| "ss link has no host".to_string())?;
            (credentials.to_string(), hostport.to_string())
        }
    };

    let (cipher, password) = match credentials.split_once(':') {
        Some((cipher, password)) => (cipher.to_string(), password.to_string()),
        None => {
            let decoded = base64_text(&credentials)
                .ok_or_else(|| "ss userinfo is not method:password".to_string())?;
            let (cipher, password) = decoded
                .split_once(':')
                .ok_or_else(|| "ss userinfo is not method:password".to_string())?;
            (cipher.to_string(), password.to_string())
        }
    };

    let (server, port) = split_host_port(&hostport)?;
    let mut map = node("ss", &display_name(fragment, &server, port), &server, port);
    insert_str(&mut map, "cipher", &cipher);
    insert_str(&mut map, "password", &password);
    insert_bool(&mut map, "udp", true);
    apply_ss_plugin(&mut map, params.get("plugin"))?;
    Ok(map)
}

/// SIP003 plugin string, e.g. `obfs-local;obfs=http;obfs-host=example.com`.
fn apply_ss_plugin(
    map: &mut HashMap<String, Value>,
    plugin: Option<&String>,
) -> Result<(), String> {
    let Some(plugin) = plugin else {
        return Ok(());
    };
    let mut parts = plugin.split(';');
    let name = parts.next().unwrap_or("").trim();
    let mut opts: Map<String, Value> = Map::new();
    for part in parts {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        opts.insert(
            key.trim().to_string(),
            Value::String(value.trim().to_string()),
        );
    }
    match name {
        "obfs-local" | "simple-obfs" | "obfs" => {
            map.insert("plugin".to_string(), Value::String("obfs".to_string()));
            let mut out = Map::new();
            if let Some(mode) = opts.get("obfs").and_then(Value::as_str) {
                out.insert("mode".to_string(), Value::String(mode.to_string()));
            }
            if let Some(host) = opts.get("obfs-host").and_then(Value::as_str) {
                out.insert("host".to_string(), Value::String(host.to_string()));
            }
            map.insert("plugin-opts".to_string(), Value::Object(out));
        }
        "v2ray-plugin" => {
            map.insert(
                "plugin".to_string(),
                Value::String("v2ray-plugin".to_string()),
            );
            let mut out = Map::new();
            out.insert("mode".to_string(), Value::String("websocket".to_string()));
            if let Some(host) = opts.get("host").and_then(Value::as_str) {
                out.insert("host".to_string(), Value::String(host.to_string()));
            }
            if let Some(path) = opts.get("path").and_then(Value::as_str) {
                out.insert("path".to_string(), Value::String(path.to_string()));
            }
            if opts.contains_key("tls") {
                out.insert("tls".to_string(), Value::Bool(true));
            }
            map.insert("plugin-opts".to_string(), Value::Object(out));
        }
        other => return Err(format!("ss plugin '{other}' is not supported")),
    }
    Ok(())
}

// ── vmess ───────────────────────────────────────────────────────────────

/// `vmess://base64(json)`; the JSON is the v2rayN "v2" object.
fn parse_vmess(rest: &str) -> Result<HashMap<String, Value>, String> {
    let (body, fragment) = split_fragment(rest);
    let decoded = base64_text(body).ok_or_else(|| "vmess payload is not base64".to_string())?;
    let json: Value =
        serde_json::from_str(&decoded).map_err(|e| format!("vmess payload is not JSON: {e}"))?;
    let field = |key: &str| -> String {
        match json.get(key) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::Bool(b)) => b.to_string(),
            _ => String::new(),
        }
    };

    let server = field("add");
    if server.is_empty() {
        return Err("vmess payload has no 'add'".to_string());
    }
    let port: u16 = field("port")
        .parse()
        .map_err(|_| "vmess payload has an invalid 'port'".to_string())?;
    let name = {
        let ps = field("ps");
        if ps.is_empty() {
            display_name(fragment, &server, port)
        } else {
            ps
        }
    };
    let mut map = node("vmess", &name, &server, port);
    insert_str(&mut map, "uuid", &field("id"));
    let alter_id = {
        let raw = field("aid");
        if raw.is_empty() {
            field("alterId")
        } else {
            raw
        }
    };
    if !alter_id.is_empty() {
        map.insert("alterId".to_string(), Value::from(alter_id.as_str()));
    }
    let cipher = {
        let scy = field("scy");
        if scy.is_empty() {
            "auto".to_string()
        } else {
            scy
        }
    };
    insert_str(&mut map, "cipher", &cipher);
    insert_bool(&mut map, "udp", true);

    let network = field("net");
    let host = field("host");
    let path = field("path");
    if !network.is_empty() {
        insert_str(&mut map, "network", &network);
    }
    match network.as_str() {
        "ws" => {
            let mut ws = Map::new();
            if !path.is_empty() {
                ws.insert("path".to_string(), Value::String(path));
            }
            if !host.is_empty() {
                let mut headers = Map::new();
                headers.insert("Host".to_string(), Value::String(host.clone()));
                ws.insert("headers".to_string(), Value::Object(headers));
            }
            map.insert("ws-opts".to_string(), Value::Object(ws));
        }
        "grpc" => {
            if !path.is_empty() {
                let mut grpc = Map::new();
                grpc.insert("grpc-service-name".to_string(), Value::String(path));
                map.insert("grpc-opts".to_string(), Value::Object(grpc));
            }
        }
        "h2" => {
            let mut h2 = Map::new();
            if !host.is_empty() {
                h2.insert(
                    "host".to_string(),
                    Value::Array(vec![Value::String(host.clone())]),
                );
            }
            if !path.is_empty() {
                h2.insert("path".to_string(), Value::String(path));
            }
            map.insert("h2-opts".to_string(), Value::Object(h2));
        }
        _ => {}
    }

    if field("tls") == "tls" {
        insert_bool(&mut map, "tls", true);
        let sni = {
            let sni = field("sni");
            if sni.is_empty() {
                host.clone()
            } else {
                sni
            }
        };
        insert_str(&mut map, "servername", &sni);
        let alpn = field("alpn");
        if !alpn.is_empty() {
            let values = alpn
                .split(',')
                .map(|item| Value::String(item.trim().to_string()))
                .collect();
            map.insert("alpn".to_string(), Value::Array(values));
        }
        let fingerprint = field("fp");
        insert_str(&mut map, "client-fingerprint", &fingerprint);
        if truthy(Some(&field("allowInsecure"))) || truthy(Some(&field("skip-cert-verify"))) {
            insert_bool(&mut map, "skip-cert-verify", true);
        }
    }
    Ok(map)
}

// ── vless / trojan (shared query shape) ─────────────────────────────────

fn parse_vless(rest: &str) -> Result<HashMap<String, Value>, String> {
    let (body, fragment) = split_fragment(rest);
    let (authority, query) = split_query(body);
    let params = query_map(query);
    let (userinfo, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "vless link has no '@'".to_string())?;
    let uuid = percent_decode(userinfo);
    let (server, port) = split_host_port(hostport)?;
    let mut map = node(
        "vless",
        &display_name(fragment, &server, port),
        &server,
        port,
    );
    insert_str(&mut map, "uuid", &uuid);
    insert_bool(&mut map, "udp", true);
    let encryption = params.get("encryption").cloned().unwrap_or_default();
    if !encryption.is_empty() {
        insert_str(&mut map, "encryption", &encryption);
    }
    insert_str(
        &mut map,
        "flow",
        params.get("flow").map_or("", String::as_str),
    );

    let security = params.get("security").map_or("", String::as_str);
    if matches!(security, "tls" | "reality" | "xtls") {
        insert_bool(&mut map, "tls", true);
    }
    if security == "reality" {
        let mut reality = Map::new();
        if let Some(pbk) = params.get("pbk") {
            reality.insert("public-key".to_string(), Value::String(pbk.clone()));
        }
        if let Some(sid) = params.get("sid") {
            reality.insert("short-id".to_string(), Value::String(sid.clone()));
        }
        map.insert("reality-opts".to_string(), Value::Object(reality));
    }
    apply_tls_common(&mut map, &params);
    apply_transport(&mut map, &params);
    Ok(map)
}

fn parse_trojan(rest: &str) -> Result<HashMap<String, Value>, String> {
    let (body, fragment) = split_fragment(rest);
    let (authority, query) = split_query(body);
    let params = query_map(query);
    let (userinfo, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "trojan link has no '@'".to_string())?;
    let password = percent_decode(userinfo);
    let (server, port) = split_host_port(hostport)?;
    let mut map = node(
        "trojan",
        &display_name(fragment, &server, port),
        &server,
        port,
    );
    insert_str(&mut map, "password", &password);
    insert_bool(&mut map, "udp", true);
    apply_tls_common(&mut map, &params);
    apply_transport(&mut map, &params);
    Ok(map)
}

/// `sni` / `insecure` / `alpn` / `fp` — the TLS knobs all three schemes
/// spell the same way.
fn apply_tls_common(map: &mut HashMap<String, Value>, params: &HashMap<String, String>) {
    if let Some(sni) = params
        .get("sni")
        .or_else(|| params.get("peer"))
        .or_else(|| params.get("servername"))
    {
        insert_str(map, "sni", sni);
    }
    if truthy(params.get("allowinsecure")) || truthy(params.get("insecure")) {
        insert_bool(map, "skip-cert-verify", true);
    }
    if let Some(alpn) = params.get("alpn") {
        let values = alpn
            .split(',')
            .map(|item| Value::String(item.trim().to_string()))
            .collect();
        map.insert("alpn".to_string(), Value::Array(values));
    }
    if let Some(fingerprint) = params.get("fp") {
        insert_str(map, "client-fingerprint", fingerprint);
    }
}

/// `type=` / `path=` / `host=` / `serviceName=` — the transport knobs.
fn apply_transport(map: &mut HashMap<String, Value>, params: &HashMap<String, String>) {
    let network = params.get("type").map_or("", String::as_str);
    if !matches!(network, "" | "tcp") {
        insert_str(map, "network", network);
    }
    let path = params.get("path").cloned().unwrap_or_default();
    let host = params.get("host").cloned().unwrap_or_default();
    match network {
        "ws" => {
            let mut ws = Map::new();
            if !path.is_empty() {
                ws.insert("path".to_string(), Value::String(path));
            }
            if !host.is_empty() {
                let mut headers = Map::new();
                headers.insert("Host".to_string(), Value::String(host));
                ws.insert("headers".to_string(), Value::Object(headers));
            }
            map.insert("ws-opts".to_string(), Value::Object(ws));
        }
        "grpc" => {
            let service = params
                .get("servicename")
                .cloned()
                .unwrap_or_else(|| path.clone());
            if !service.is_empty() {
                let mut grpc = Map::new();
                grpc.insert("grpc-service-name".to_string(), Value::String(service));
                map.insert("grpc-opts".to_string(), Value::Object(grpc));
            }
        }
        "h2" | "http" => {
            let mut h2 = Map::new();
            if !host.is_empty() {
                h2.insert("host".to_string(), Value::Array(vec![Value::String(host)]));
            }
            if !path.is_empty() {
                h2.insert("path".to_string(), Value::String(path));
            }
            map.insert("h2-opts".to_string(), Value::Object(h2));
        }
        _ => {}
    }
}

// ── hysteria2 / anytls ──────────────────────────────────────────────────

fn parse_hysteria2(rest: &str) -> Result<HashMap<String, Value>, String> {
    let (body, fragment) = split_fragment(rest);
    let (authority, query) = split_query(body);
    let params = query_map(query);
    let (userinfo, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "hysteria2 link has no '@'".to_string())?;
    let password = percent_decode(userinfo);
    let (server, port) = split_host_port(hostport)?;
    let mut map = node(
        "hysteria2",
        &display_name(fragment, &server, port),
        &server,
        port,
    );
    insert_str(&mut map, "password", &password);
    apply_tls_common(&mut map, &params);
    if let Some(obfs) = params.get("obfs") {
        insert_str(&mut map, "obfs", obfs);
    }
    if let Some(obfs_password) = params.get("obfs-password") {
        insert_str(&mut map, "obfs-password", obfs_password);
    }
    if let Some(up) = params.get("up") {
        insert_str(&mut map, "up", up);
    }
    if let Some(down) = params.get("down") {
        insert_str(&mut map, "down", down);
    }
    Ok(map)
}

fn parse_anytls(rest: &str) -> Result<HashMap<String, Value>, String> {
    let (body, fragment) = split_fragment(rest);
    let (authority, query) = split_query(body);
    let params = query_map(query);
    let (userinfo, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "anytls link has no '@'".to_string())?;
    let password = percent_decode(userinfo);
    let (server, port) = split_host_port(hostport)?;
    let mut map = node(
        "anytls",
        &display_name(fragment, &server, port),
        &server,
        port,
    );
    insert_str(&mut map, "password", &password);
    apply_tls_common(&mut map, &params);
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(content: &str) -> HashMap<String, Value> {
        let mut nodes = parse_share_links(content).expect("payload parses");
        assert_eq!(nodes.len(), 1, "expected a single node");
        nodes.remove(0)
    }

    fn string(map: &HashMap<String, Value>, key: &str) -> String {
        map.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    /// SIP002: base64 userinfo, explicit plugin, percent-encoded tag.
    #[test]
    fn parses_ss_sip002_with_obfs_plugin() {
        let link = "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388\
                    ?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#%E9%A6%99%E6%B8%AF%2001";
        let node = single(link);
        assert_eq!(string(&node, "type"), "ss");
        assert_eq!(string(&node, "server"), "example.com");
        assert_eq!(node.get("port").and_then(Value::as_u64), Some(8388));
        assert_eq!(string(&node, "cipher"), "aes-128-gcm");
        assert_eq!(string(&node, "password"), "pass");
        assert_eq!(string(&node, "name"), "香港 01");
        assert_eq!(string(&node, "plugin"), "obfs");
        let opts = node.get("plugin-opts").and_then(Value::as_object).unwrap();
        assert_eq!(opts.get("mode").and_then(Value::as_str), Some("http"));
        assert_eq!(opts.get("host").and_then(Value::as_str), Some("bing.com"));
    }

    /// Legacy form: the whole `method:password@host:port` is base64.
    #[test]
    fn parses_ss_legacy_fully_encoded() {
        let body = base64::engine::general_purpose::STANDARD
            .encode("chacha20-ietf-poly1305:secret@127.0.0.1:443");
        let node = single(&format!("ss://{body}#legacy"));
        assert_eq!(string(&node, "server"), "127.0.0.1");
        assert_eq!(node.get("port").and_then(Value::as_u64), Some(443));
        assert_eq!(string(&node, "cipher"), "chacha20-ietf-poly1305");
        assert_eq!(string(&node, "name"), "legacy");
    }

    #[test]
    fn parses_vmess_websocket_tls() {
        let json = r#"{"v":"2","ps":"Tokyo","add":"jp.example.com","port":"443",
            "id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto",
            "net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"sni.example.com"}"#;
        let body = base64::engine::general_purpose::STANDARD.encode(json);
        let node = single(&format!("vmess://{body}"));
        assert_eq!(string(&node, "type"), "vmess");
        assert_eq!(string(&node, "name"), "Tokyo");
        assert_eq!(
            string(&node, "uuid"),
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(string(&node, "network"), "ws");
        assert_eq!(string(&node, "servername"), "sni.example.com");
        assert_eq!(node.get("tls").and_then(Value::as_bool), Some(true));
        let ws = node.get("ws-opts").and_then(Value::as_object).unwrap();
        assert_eq!(ws.get("path").and_then(Value::as_str), Some("/ws"));
    }

    #[test]
    fn parses_vless_reality() {
        let link = "vless://22222222-3333-4444-5555-666666666666@1.2.3.4:443\
                    ?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome\
                    &pbk=PUBKEY&sid=abcd&flow=xtls-rprx-vision&type=tcp#Reality%20HK";
        let node = single(link);
        assert_eq!(string(&node, "type"), "vless");
        assert_eq!(string(&node, "name"), "Reality HK");
        assert_eq!(node.get("tls").and_then(Value::as_bool), Some(true));
        assert_eq!(string(&node, "flow"), "xtls-rprx-vision");
        assert_eq!(string(&node, "client-fingerprint"), "chrome");
        let reality = node.get("reality-opts").and_then(Value::as_object).unwrap();
        assert_eq!(
            reality.get("public-key").and_then(Value::as_str),
            Some("PUBKEY")
        );
        assert_eq!(
            reality.get("short-id").and_then(Value::as_str),
            Some("abcd")
        );
    }

    #[test]
    fn parses_trojan_grpc() {
        let link = "trojan://pass%40word@example.com:443?type=grpc\
                    &serviceName=svc&sni=example.com&allowInsecure=1#Trojan";
        let node = single(link);
        assert_eq!(string(&node, "password"), "pass@word");
        assert_eq!(string(&node, "network"), "grpc");
        assert_eq!(
            node.get("skip-cert-verify").and_then(Value::as_bool),
            Some(true)
        );
        let grpc = node.get("grpc-opts").and_then(Value::as_object).unwrap();
        assert_eq!(
            grpc.get("grpc-service-name").and_then(Value::as_str),
            Some("svc")
        );
    }

    #[test]
    fn parses_hysteria2_with_obfs() {
        let link = "hysteria2://secret@example.com:8443?sni=example.com\
                    &insecure=1&obfs=salamander&obfs-password=cfn#HY2";
        let node = single(link);
        assert_eq!(string(&node, "type"), "hysteria2");
        assert_eq!(string(&node, "obfs"), "salamander");
        assert_eq!(string(&node, "obfs-password"), "cfn");
        assert_eq!(
            node.get("skip-cert-verify").and_then(Value::as_bool),
            Some(true)
        );
    }

    /// The real airport shape: a base64 body holding several links, URL-safe
    /// alphabet without padding.
    #[test]
    fn decodes_url_safe_unpadded_base64_body() {
        let body = "ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n\
                    trojan://pw@b.example.com:443#B\n";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body);
        let nodes = parse_share_links(&encoded).expect("payload parses");
        assert_eq!(nodes.len(), 2);
        assert_eq!(string(&nodes[0], "name"), "A");
        assert_eq!(string(&nodes[1], "name"), "B");
    }

    #[test]
    fn plain_link_list_is_accepted() {
        let nodes = parse_share_links(
            "# comment line\nss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#A\n",
        )
        .expect("payload parses");
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn unsupported_scheme_is_rejected() {
        let err = parse_share_links("ssr://c29tZSBzc3IgYm9keQ").unwrap_err();
        assert!(err.contains("no share link"), "unexpected error: {err}");
    }

    #[test]
    fn malformed_payload_is_not_a_link_list() {
        assert!(parse_share_links("<html><body>blocked</body></html>").is_err());
    }
}
