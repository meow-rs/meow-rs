//! Tiny HTTP/1.1 GET client for every internal fetch (subscriptions,
//! proxy/rule providers, geodata, the optional external UI).
//!
//! Dials either directly — through `meow_common::connect_tcp_host`, so the
//! host app's resolver / `SocketProtector` hooks apply — or through a meow
//! `Proxy` adapter, so fetches that target GFW-blocked hosts like
//! `raw.githubusercontent.com` can route through one of the user's upstream
//! nodes. HTTPS goes through `meow_transport::tls::TlsLayer` (BoringSSL), the
//! same stack the proxies use; there is no separate HTTP-client TLS.
//!
//! Scope is intentionally minimal:
//!   * `GET` only.
//!   * HTTP/1.1, `Connection: close`, `Accept-Encoding: identity`.
//!   * Follows up to 5 redirects (`3xx` with `Location`).
//!   * No streaming — full body buffered in memory, capped at
//!     `MAX_BODY_BYTES` (256 MiB).

use anyhow::{anyhow, bail, Result};
use meow_common::adapter::Proxy;
use meow_common::metadata::Metadata;
use meow_common::{connect_tcp_host, ConnType, Network};
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::Transport as _;
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;
use url::Url;

const MAX_REDIRECTS: u8 = 5;
/// Bounds the proxy dial and the TLS handshake. Without it, a fetch through
/// an unreachable upstream (e.g. rule-provider load at startup while the
/// network is down) inherits the adapter's connect behaviour — which for some
/// protocols never times out — and stalls the caller indefinitely
/// (BaoLianDeng#79: config update froze the app until force quit).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const USER_AGENT: &str = concat!("clash.meta/", env!("CARGO_PKG_VERSION"));
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024 * 1024; // 256 MiB hard ceiling
/// Headroom on top of the body cap for the status line + headers.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Header names this client writes itself or that frame the request, so a
/// user-supplied entry with one of these names is dropped instead of emitted
/// (RFC 9110 §7.6.1 hop-by-hop set plus the framing lines `fetch_one`
/// controls). Mirrors Go `net/http`'s `reqWriteExcludeHeader`: a second
/// `Host:`/`Content-Length:` line is a request-smuggling primitive, and a
/// configured `Accept-Encoding: gzip` would return an undecodable body.
/// `User-Agent` is not listed — it is handled by replace semantics instead.
const RESERVED_HEADER_NAMES: [&str; 12] = [
    "host",
    "connection",
    "content-length",
    "accept-encoding",
    "transfer-encoding",
    "trailer",
    "te",
    "upgrade",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
];

fn is_reserved_header(name: &str) -> bool {
    RESERVED_HEADER_NAMES
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// RFC 9110 `tchar` set (token characters): the ONLY bytes a header field
/// name may contain. Go's writer enforces the same via `httpguts
/// .ValidHeaderFieldName`.
#[inline]
fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
        | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// A valid header field name is non-empty and all-tchar. In particular this
/// rejects whitespace around/between the name and the colon (`"Host "`,
/// `" Host"`, `"Host\t"`, `"Ho st"`) and any non-ASCII byte: such names miss
/// the exact-match reserved-name filter below and would be emitted as
/// `Host : evil`, which tolerant intermediaries can normalize back to a
/// second `Host:` line — a parser-differential request-smuggling input.
/// Names are rejected, never trimmed/rewritten.
#[inline]
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_tchar)
}

/// A valid header field value per RFC 9110/Go's `ValidHeaderFieldValue`:
/// SP, HTAB, and any byte in the visible range plus 0x80..=0xFF (obs
/// latin-1 values are tolerated, matching Go); every other CTL (including
/// CR/LF, 0x00-0x08, 0x0A-0x1F, DEL) is rejected.
#[inline]
fn is_valid_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b'\x20'..=b'\x7e').contains(&b) || b >= 0x80)
}

/// Resolve a `proxy:`-style download-proxy field against the published route
/// map: absent, empty, or `DIRECT` fetch direct; any other name must resolve
/// to a built proxy or group. An unresolvable name fails the fetch loudly —
/// the alternative (silently falling back to direct) would leak egress past a
/// chain the config declared (issue #625).
pub fn resolve_download_proxy(
    registry: &meow_proxy::dialer::ProxyRegistry,
    name: Option<&str>,
) -> Result<Option<Arc<dyn Proxy>>> {
    match name {
        None | Some("") => Ok(None),
        // Whitespace-only is almost surely a typo — reject rather than
        // silently downgrading to a direct fetch (same posture as
        // `dialer-proxy`, proxy_provider.rs).
        Some(s) if s.trim().is_empty() => Err(anyhow!(
            "download proxy name is blank — expected a proxy/group name or DIRECT"
        )),
        Some(s) => {
            let name = s.trim();
            if name.eq_ignore_ascii_case("DIRECT") {
                return Ok(None);
            }
            registry
                .resolve_name(name)
                .map(Some)
                .ok_or_else(|| anyhow!("download proxy '{name}' is not a known proxy or group"))
        }
    }
}

/// Fetch `url` via `proxy` and return the response body.
///
/// Follows up to 5 redirects (302/301/307/308). Returns an
/// error for non-2xx terminal responses, oversize bodies, or transport errors.
pub async fn fetch_via_proxy(url: &str, proxy: &Arc<dyn Proxy>) -> Result<Vec<u8>> {
    fetch(url, Some(proxy), &[]).await
}

/// Fetch `url` over a direct connection (no proxy) and return the body.
pub async fn fetch_direct(url: &str) -> Result<Vec<u8>> {
    fetch(url, None, &[]).await
}

/// Fetch `url`, directly or via `proxy`, sending `headers` in addition to the
/// defaults, and return the response body.
///
/// Follows up to 5 redirects (302/301/307/308). Returns an error for non-2xx
/// terminal responses, oversize bodies, or transport errors.
pub async fn fetch(
    url: &str,
    proxy: Option<&Arc<dyn Proxy>>,
    headers: &[(String, String)],
) -> Result<Vec<u8>> {
    fetch_capped(url, proxy, headers, MAX_BODY_BYTES).await
}

/// [`fetch`] with the body cap as a parameter, so tests can exercise the
/// oversize paths without transferring hundreds of megabytes.
async fn fetch_capped(
    url: &str,
    proxy: Option<&Arc<dyn Proxy>>,
    headers: &[(String, String)],
    limit: usize,
) -> Result<Vec<u8>> {
    let mut current = Url::parse(url).map_err(|e| anyhow!("invalid URL '{url}': {e}"))?;
    let mut headers = headers.to_vec();
    for _ in 0..=MAX_REDIRECTS {
        match fetch_one(&current, proxy, &headers, limit).await? {
            Outcome::Body(bytes) => return Ok(bytes),
            Outcome::Redirect(next) => {
                let next = current
                    .join(&next)
                    .map_err(|e| anyhow!("bad redirect Location '{next}': {e}"))?;
                if current.origin() != next.origin() {
                    headers.retain(|(name, _)| {
                        ![
                            "authorization",
                            "cookie",
                            "cookie2",
                            "proxy-authorization",
                            "www-authenticate",
                        ]
                        .iter()
                        .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
                    });
                }
                current = next;
            }
        }
    }
    bail!("too many redirects (> {MAX_REDIRECTS}) starting from {url}")
}

enum Outcome {
    Body(Vec<u8>),
    Redirect(String),
}

async fn fetch_one(
    url: &Url,
    proxy: Option<&Arc<dyn Proxy>>,
    headers: &[(String, String)],
    limit: usize,
) -> Result<Outcome> {
    let scheme = url.scheme();
    let is_https = match scheme {
        "https" => true,
        "http" => false,
        other => bail!("unsupported URL scheme '{other}': {url}"),
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL has no host: {url}"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL has no port: {url}"))?;
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };

    let conn: Box<dyn meow_transport::Stream> = match proxy {
        Some(proxy) => {
            let metadata = Metadata {
                network: Network::Tcp,
                conn_type: ConnType::Http,
                host: SmolStr::from(&host),
                dst_port: port,
                // Provider/geodata/subscription fetches are housekeeping —
                // a `lazy` group serving this dial must not count it as use.
                internal: true,
                ..Metadata::default()
            };
            let conn = tokio::time::timeout(CONNECT_TIMEOUT, proxy.dial_tcp(&metadata))
                .await
                .map_err(|_| {
                    anyhow!(
                        "dial via proxy '{}' timed out after {CONNECT_TIMEOUT:?}",
                        proxy.name()
                    )
                })?
                .map_err(|e| anyhow!("dial via proxy '{}': {e}", proxy.name()))?;
            Box::new(conn)
        }
        None => {
            // Resolver-aware direct dial: honours the host app's
            // `HostResolver` / `SocketProtector` hooks (VPN apps), then falls
            // back to the system resolver.
            let host_str = host.trim_start_matches('[').trim_end_matches(']');
            let conn = tokio::time::timeout(CONNECT_TIMEOUT, connect_tcp_host(host_str, port))
                .await
                .map_err(|_| {
                    anyhow!("connect to {host}:{port} timed out after {CONNECT_TIMEOUT:?}")
                })?
                .map_err(|e| anyhow!("connect to {host}:{port}: {e}"))?;
            Box::new(conn)
        }
    };

    // mihomo parity (component/http/http.go): a user-supplied User-Agent
    // replaces the built-in one instead of duplicating the field line.
    let has_custom_ua = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"));
    let mut request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Accept: */*\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n",
        path = path_and_query,
        host_header = host_header(&host, port, is_https),
    );
    if !has_custom_ua {
        request.push_str("User-Agent: ");
        request.push_str(USER_AGENT);
        request.push_str("\r\n");
    }
    for (name, value) in headers {
        // Full RFC 9110 token validation — NOT a mere CR/LF/colon check:
        // `"Host "`/`" Host"`/`"Host\t"` would dodge the reserved-name match
        // below and be emitted as `Host : evil`, which tolerant intermediaries
        // can normalize into a second `Host:` line (request smuggling).
        // Names/values are rejected as-is, never trimmed or rewritten.
        if !is_valid_header_name(name) || !is_valid_header_value(value) {
            bail!("invalid HTTP header {name:?}");
        }
        if is_reserved_header(name) {
            // mihomo parity (net/http reqWriteExcludeHeader): never let a
            // user header duplicate or override the request's own framing
            // lines — a second `Host:`/`Content-Length:` is a classic
            // request-smuggling primitive, and a configured
            // `Accept-Encoding: gzip` would return a body meow can't decode.
            debug!("ignoring reserved provider header {name:?}");
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    let mut stream = if is_https {
        // Same TlsLayer the proxies dial with (BoringSSL).
        let tls = TlsLayer::new(&TlsConfig::new(
            host.trim_start_matches('[').trim_end_matches(']'),
        ))
        .map_err(|e| anyhow!("invalid TLS server name '{host}': {e}"))?;
        tokio::time::timeout(CONNECT_TIMEOUT, tls.connect(conn))
            .await
            .map_err(|_| anyhow!("TLS handshake to {host} timed out after {CONNECT_TIMEOUT:?}"))?
            .map_err(|e| anyhow!("TLS handshake to {host}: {e}"))?
    } else {
        conn
    };
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_response(&mut stream, limit).await
}

fn host_header(host: &str, port: u16, is_https: bool) -> String {
    let default_port = if is_https { 443 } else { 80 };
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

async fn read_response<S>(stream: &mut S, limit: usize) -> Result<Outcome>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Read until EOF with a wall-clock timeout. Connection: close means
    // the server signals end-of-body by closing the socket. The read cap is
    // the body cap plus header headroom; the exact body-size checks happen
    // in `parse_response` once the framing is known.
    let read_cap = limit.saturating_add(MAX_HEADER_BYTES);
    let mut buf = Vec::with_capacity(64 * 1024);
    let read = async {
        let mut tmp = [0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            if buf.len() + n > read_cap {
                bail!("response exceeds max body size ({limit} bytes)");
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Result::<()>::Ok(())
    };
    tokio::time::timeout(READ_TIMEOUT, read)
        .await
        .map_err(|_| anyhow!("response read timed out after {READ_TIMEOUT:?}"))??;

    parse_response(&buf, limit)
}

fn parse_response(buf: &[u8], limit: usize) -> Result<Outcome> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let parsed = resp
        .parse(buf)
        .map_err(|e| anyhow!("response parse error: {e}"))?;
    let body_start = match parsed {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => bail!("incomplete HTTP response (no header terminator)"),
    };
    let status = resp
        .code
        .ok_or_else(|| anyhow!("response missing status code"))?;

    if (300..400).contains(&status) {
        for h in resp.headers.iter() {
            if h.name.eq_ignore_ascii_case("location") {
                let loc = std::str::from_utf8(h.value)
                    .map_err(|e| anyhow!("non-UTF-8 Location header: {e}"))?;
                return Ok(Outcome::Redirect(loc.to_string()));
            }
        }
        bail!("HTTP {status} redirect without Location header");
    }
    if !(200..300).contains(&status) {
        let snippet: String = String::from_utf8_lossy(&buf[body_start..])
            .chars()
            .take(200)
            .collect();
        if snippet.is_empty() {
            bail!("HTTP {status}");
        }
        bail!("HTTP {status}: {snippet}");
    }
    // A declared Content-Length above the cap is rejected outright (issue
    // #431) — a dishonest or huge value must not be trusted over the cap.
    let mut content_length = None;
    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            let declared = std::str::from_utf8(h.value)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .ok_or_else(|| anyhow!("invalid Content-Length header"))?;
            if declared > limit as u64 {
                bail!("response exceeds max body size ({limit} bytes)");
            }
            if content_length.is_some_and(|previous| previous != declared) {
                bail!("conflicting Content-Length headers");
            }
            content_length = Some(declared);
        }
    }
    let chunked = resp.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(header.value).is_ok_and(|value| {
                value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("chunked"))
            })
    });
    let body = if chunked {
        decode_chunked(&buf[body_start..], limit)?
    } else {
        let body = &buf[body_start..];
        if content_length.is_some_and(|declared| declared != body.len() as u64) {
            bail!("response body length does not match Content-Length");
        }
        if body.len() > limit {
            bail!("response exceeds max body size ({limit} bytes)");
        }
        body.to_vec()
    };
    Ok(Outcome::Body(body))
}

fn decode_chunked(mut input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("incomplete chunk-size line"))?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|e| anyhow!("non-UTF-8 chunk size: {e}"))?;
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|e| anyhow!("invalid chunk size '{size_text}': {e}"))?;
        input = &input[line_end + 2..];

        if size == 0 {
            // A zero chunk is followed by optional trailers and a final CRLF.
            if input == b"\r\n" || input.windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok(body);
            }
            bail!("incomplete chunked response trailers");
        }
        if size > limit.saturating_sub(body.len()) {
            bail!("response exceeds max body size ({limit} bytes)");
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            bail!("incomplete chunk data");
        }
        body.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

/// Pick the first proxy named in the user's `proxies:` config block and look
/// it up in the supplied proxy map.
///
/// Returns `None` if there are no `proxies:` entries, if the first entry has
/// no `name:` field, or if that name isn't in the map (e.g. it failed to
/// load during proxy construction).
pub fn first_named_proxy(
    raw_proxies: Option<&[std::collections::HashMap<String, serde_yaml::Value>]>,
    proxies: &std::collections::HashMap<smol_str::SmolStr, Arc<dyn Proxy>>,
) -> Option<Arc<dyn Proxy>> {
    let entry = raw_proxies?.first()?;
    let name = entry.get("name")?.as_str()?;
    proxies.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_decodes_chunked_body_and_extensions() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n";
        match parse_response(response, MAX_BODY_BYTES).unwrap() {
            Outcome::Body(body) => assert_eq!(body, b"Wikipedia"),
            Outcome::Redirect(_) => panic!("unexpected redirect"),
        }
    }

    #[test]
    fn parse_response_rejects_truncated_chunk() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc";
        assert!(parse_response(response, MAX_BODY_BYTES).is_err());
    }

    /// `Proxy` whose `dial_tcp` never completes — models an adapter dialing an
    /// unreachable upstream with no protocol-level connect timeout.
    struct HangingProxy {
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for HangingProxy {
        fn name(&self) -> &str {
            "hang"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            _m: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            std::future::pending().await
        }
        async fn dial_udp(
            &self,
            _m: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Err(meow_common::MeowError::NotSupported(
                "hang: dial_udp".into(),
            ))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl Proxy for HangingProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    // start_paused: tokio auto-advances the clock when every task is idle, so
    // the CONNECT_TIMEOUT fires immediately instead of after a real 15 s.
    #[tokio::test(start_paused = true)]
    async fn connect_timeout_bounds_hung_dial() {
        let proxy: Arc<dyn Proxy> = Arc::new(HangingProxy {
            health: meow_common::ProxyHealth::new(),
        });
        let err = fetch_via_proxy("http://192.0.2.1/rules.yaml", &proxy)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("timed out"),
            "expected connect timeout, got: {err}"
        );
    }

    /// Spawns a bare TCP server on `127.0.0.1` that writes `raw_response`
    /// verbatim to the first connection it accepts, then returns its URL.
    async fn spawn_raw_http_server(raw_response: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            // Drain (part of) the request so the exchange is well-formed;
            // the response below doesn't depend on what was sent.
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(raw_response).await;
            let _ = stream.shutdown().await;
        });
        format!("http://{addr}/")
    }

    // Regression test for issue #431: a dishonest (or merely huge)
    // Content-Length must be rejected before any of the body is read.
    #[tokio::test]
    async fn response_bytes_capped_rejects_oversize_content_length() {
        let url =
            spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nshort").await;
        let err = fetch_capped(&url, None, &[], 16).await.unwrap_err();
        assert!(
            err.to_string().contains("exceeds max body size"),
            "unexpected error: {err}"
        );
    }

    // Regression test for issue #431: with no (or an absent) Content-Length
    // — e.g. chunked encoding — the streaming cap must still catch an
    // oversized body instead of buffering it in full.
    #[tokio::test]
    async fn response_bytes_capped_rejects_oversize_stream_without_content_length() {
        let url = spawn_raw_http_server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n",
        )
        .await;
        let err = fetch_capped(&url, None, &[], 8).await.unwrap_err();
        assert!(
            err.to_string().contains("exceeds max body size"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn response_bytes_capped_accepts_body_within_limit() {
        let url = spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
        let bytes = fetch_capped(&url, None, &[], 16).await.unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn direct_fetch_rejects_truncated_content_length() {
        let url = spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").await;
        let error = fetch_direct(&url).await.unwrap_err();
        assert!(error.to_string().contains("does not match Content-Length"));
    }

    #[test]
    fn content_length_framing_rejects_extra_bytes_and_conflicting_lengths() {
        for response in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc"[..],
        ] {
            assert!(parse_response(response, MAX_BODY_BYTES).is_err());
        }
        assert!(
            matches!(parse_response(b"HTTP/1.1 200 OK\r\n\r\nabc", MAX_BODY_BYTES).unwrap(), Outcome::Body(body) if body == b"abc")
        );
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        String::from_utf8(request).unwrap().to_ascii_lowercase()
    }

    #[tokio::test]
    async fn redirects_preserve_same_origin_headers_and_strip_cross_origin_credentials() {
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/start", origin.local_addr().unwrap());
        let destination = format!("http://{}/end", other.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for location in ["/same-origin", &destination] {
                let (mut stream, _) = origin.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert!(request.contains("authorization: bearer test-token\r\n"));
                assert!(request.contains("cookie: session=test\r\n"));
                stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
            }
            let (mut stream, _) = other.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            for name in [
                "authorization",
                "cookie",
                "cookie2",
                "proxy-authorization",
                "www-authenticate",
            ] {
                assert!(!request.contains(&format!("\r\n{name}:")), "leaked {name}");
            }
            assert!(request.contains("x-custom: retained\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        let headers = [
            ("AuThOrIzAtIoN", "Bearer test-token"),
            ("Cookie", "session=test"),
            ("Cookie2", "test"),
            ("Proxy-Authorization", "test"),
            ("WWW-Authenticate", "test"),
            ("X-Custom", "retained"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));
        let body = tokio::time::timeout(Duration::from_secs(5), fetch(&url, None, &headers))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, b"ok");
        server.await.unwrap();
    }

    // User headers must never duplicate or override the request's own
    // framing lines — a second `Host:` is a request-smuggling primitive, a
    // custom `Accept-Encoding: gzip` an undecodable body.
    #[tokio::test]
    async fn reserved_header_names_are_dropped_at_emission() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/rules.yaml", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            request
        });
        let headers = [
            ("Host", "evil.example.com"),
            ("Content-Length", "999"),
            ("Accept-Encoding", "gzip"),
            ("Connection", "keep-alive"),
            ("X-Custom", "kept"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));
        let body = tokio::time::timeout(Duration::from_secs(5), fetch(&url, None, &headers))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, b"ok");
        let request = server.await.unwrap();
        // Custom non-reserved header reaches the wire...
        assert!(request.contains("x-custom: kept\r\n"));
        // ...but each framing line appears exactly once, with this
        // client's own value — the configured ones never made it out.
        assert_eq!(
            request.lines().filter(|l| l.starts_with("host:")).count(),
            1
        );
        assert!(request.contains("accept-encoding: identity\r\n"));
        assert_eq!(
            request
                .lines()
                .filter(|l| l.starts_with("accept-encoding:"))
                .count(),
            1
        );
        assert!(request.contains("connection: close\r\n"));
        assert!(!request.contains("content-length: 999"));
    }

    // The `bail!("invalid HTTP header")` guard — CRLF in a
    // header value is a header-injection attempt, not a fetch error to
    // paper over.
    #[tokio::test]
    async fn header_values_with_crlf_are_rejected() {
        let url = spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let headers = vec![("X-Bad".to_string(), "evil\r\nHost: injected".to_string())];
        let err = tokio::time::timeout(Duration::from_secs(5), fetch(&url, None, &headers))
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid HTTP header"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn header_names_with_colons_are_rejected() {
        let url = spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let headers = vec![("X-Bad:injected".to_string(), "v".to_string())];
        let err = tokio::time::timeout(Duration::from_secs(5), fetch(&url, None, &headers))
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid HTTP header"),
            "unexpected error: {err}"
        );
    }

    // `"Host "`, `" Host"`, `"Host\t"` are not RFC 9110 tokens: they dodge
    // the exact reserved-name match and would be emitted as `Host : evil`,
    // which a tolerant intermediary can normalize into a second `Host:`
    // line (parser-differential request smuggling). Names must be rejected,
    // not trimmed.
    #[tokio::test]
    async fn header_names_with_padding_whitespace_are_rejected() {
        // One single-shot server per case: an invalid-header fetch still
        // dials before bailing, so a shared server would be consumed.
        for name in ["Host ", " Host", "Host\t", "Ho st", "Content-Length "] {
            let url =
                spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let headers = vec![(name.to_string(), "evil".to_string())];
            let err = tokio::time::timeout(Duration::from_secs(5), fetch(&url, None, &headers))
                .await
                .unwrap()
                .unwrap_err();
            assert!(
                err.to_string().contains("invalid HTTP header"),
                "name {name:?} should be rejected as a non-token header name: {err}"
            );
        }
    }

    // Non-token bytes beyond whitespace: non-ASCII (Unicode), DEL, and other
    // separators must all be rejected too — the whole tchar table applies.
    #[tokio::test]
    async fn header_names_with_non_token_bytes_are_rejected() {
        for name in [
            "Hösí",
            "Host\u{7f}",
            "Host\u{0b}",
            "()",
            "Host\\",
            "Host\x1f",
        ] {
            let url =
                spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let headers = vec![(name.to_string(), "v".to_string())];
            let err = tokio::time::timeout(Duration::from_secs(5), fetch(&url, None, &headers))
                .await
                .unwrap()
                .unwrap_err();
            assert!(
                err.to_string().contains("invalid HTTP header"),
                "name {name:?} should be rejected as a non-token header name: {err}"
            );
        }
    }

    // Values may only contain SP, HTAB, and visible/8-bit bytes (Go
    // `ValidHeaderFieldValue`); other CTLs (NUL, vertical tab, DEL) are
    // injection primitives.
    #[tokio::test]
    async fn header_values_with_control_characters_are_rejected() {
        for value in ["evil\u{0}x", "evil\u{0b}x", "evil\u{7f}x"] {
            let url =
                spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let headers = vec![("X-Test".to_string(), value.to_string())];
            let err = tokio::time::timeout(Duration::from_secs(5), fetch(&url, None, &headers))
                .await
                .unwrap()
                .unwrap_err();
            assert!(
                err.to_string().contains("invalid HTTP header"),
                "value {value:?} should be rejected: {err}"
            );
        }
        // SP and HTAB ARE legal field-value bytes — round-trip one.
        let url = spawn_raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let headers = vec![("X-Test".to_string(), "a \t b".to_string())];
        let body = tokio::time::timeout(Duration::from_secs(5), fetch(&url, None, &headers))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, b"ok");
    }

    /// `Proxy` that records the `Metadata` of every `dial_tcp` and refuses
    /// the connection — pins the `internal` marker on housekeeping fetches
    /// (#555): a `lazy` group serving provider/geodata downloads must not
    /// count them as use.
    struct CapturingMetaProxy {
        seen: std::sync::Mutex<Vec<Metadata>>,
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for CapturingMetaProxy {
        fn name(&self) -> &str {
            "capture"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            m: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            self.seen.lock().unwrap().push(m.clone());
            Err(meow_common::MeowError::NotSupported(
                "capture mock refuses connections".into(),
            ))
        }
        async fn dial_udp(
            &self,
            _m: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            unimplemented!("capture mock has no UDP")
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl Proxy for CapturingMetaProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn fetch_via_proxy_marks_metadata_internal() {
        let proxy = Arc::new(CapturingMetaProxy {
            seen: std::sync::Mutex::new(Vec::new()),
            health: meow_common::ProxyHealth::new(),
        });
        let dyn_proxy: Arc<dyn Proxy> = Arc::<CapturingMetaProxy>::clone(&proxy);
        let _ = fetch_via_proxy("http://192.0.2.1/rules.yaml", &dyn_proxy).await;
        let seen = proxy.seen.lock().unwrap();
        let meta = seen.first().expect("the fetch must reach dial_tcp");
        assert!(
            meta.internal,
            "provider/geodata downloads are housekeeping — a lazy group \
             must not count them as use"
        );
        assert_eq!(meta.conn_type, ConnType::Http);
    }

    /// `resolve_download_proxy` (issue #625): absent/empty/`DIRECT` fetch
    /// direct, a published name resolves to its entry, anything else fails
    /// closed — a silent direct fallback would leak egress past a chain the
    /// config declared. Whitespace-only is rejected like `dialer-proxy` —
    /// a typo must not silently downgrade to direct either.
    #[test]
    fn resolve_download_proxy_variants() {
        let registry = meow_proxy::dialer::ProxyRegistry::default();
        for absent in [
            None,
            Some(""),
            Some("DIRECT"),
            Some("direct"),
            Some(" DIRECT "),
        ] {
            let resolved = resolve_download_proxy(&registry, absent).unwrap();
            assert!(resolved.is_none(), "{absent:?} must fetch direct");
        }
        assert!(resolve_download_proxy(&registry, Some("   ")).is_err());
        // Unpublished registry: every real name is unresolvable.
        assert!(resolve_download_proxy(&registry, Some("front")).is_err());

        let front: Arc<dyn Proxy> = Arc::new(CapturingMetaProxy {
            seen: std::sync::Mutex::new(Vec::new()),
            health: meow_common::ProxyHealth::new(),
        });
        registry.publish(Arc::new(std::collections::HashMap::from([(
            SmolStr::from("front"),
            Arc::clone(&front),
        )])));
        let resolved = resolve_download_proxy(&registry, Some("front"))
            .unwrap()
            .expect("published name resolves");
        assert!(Arc::ptr_eq(&resolved, &front));
        // Surrounding whitespace is trimmed before lookup.
        assert!(resolve_download_proxy(&registry, Some(" front ")).is_ok());
        assert!(resolve_download_proxy(&registry, Some("missing")).is_err());
    }
}
