use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use meow_common::{Proxy, ProxyAdapter};
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::Transport as _;
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

pub use meow_common::ProxyHealth;

pub const GROUP_DELAY_CONCURRENCY: usize = 16;
pub const PROVIDER_HEALTHCHECK_CONCURRENCY: usize = 10;
pub const GLOBAL_DELAY_PROBE_CONCURRENCY: usize = 32;

#[derive(Debug)]
pub struct NamedProbeResult {
    pub name: String,
    pub delay: u16,
    pub error: Option<UrlTestError>,
}

/// Outcome of a single [`url_test`] probe. Callers distinguish transport
/// failure from deadline expiry to pick the right HTTP status code
/// (upstream: 503 vs 504 — see `docs/specs/api-delay-endpoints.md`).
#[derive(Debug, Clone)]
pub enum UrlTestError {
    Timeout,
    Transport(String),
}

/// Probe a proxy by dialing the target, issuing an HTTP/1.1 `GET`, and
/// reading the status line. Returns the total elapsed milliseconds on
/// success (status within `expected`), otherwise a classified error.
///
/// `expected` is a comma-separated list of status-code ranges
/// (e.g. `"200"`, `"200-299"`, `"200,204-206"`). When `None`, any 2xx
/// status counts as success — matching upstream Go mihomo's default in
/// `component/proxydialer/http.go::httpHealthCheck`.
///
/// `https://` targets are tunneled through a client-side TLS handshake
/// (`meow_transport::tls::TlsLayer`, BoringSSL by default) before the GET. HTTP targets go over the raw
/// dialed connection.
pub async fn url_test(
    adapter: &dyn ProxyAdapter,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, UrlTestError> {
    let Some(parsed) = ParsedUrl::parse(url) else {
        return Err(UrlTestError::Transport(format!("invalid url: {url}")));
    };
    let ranges = match parse_expected(expected) {
        Ok(r) => r,
        Err(e) => return Err(UrlTestError::Transport(e)),
    };

    let start = Instant::now();
    // `Tunnel` marks this dial as a health probe rather than user traffic.
    // mihomo solves the same problem by threading an explicit `touch` flag
    // through its group calls (`fast(false)` for probes); meow-rs'
    // `ProxyAdapter` trait has no such parameter, so the marker rides on
    // the metadata instead.  Groups skip the usage-generation bump for
    // these dials — counting probes as "use" would defeat lazy health
    // checks for nested groups.  No production dialer sets
    // `ConnType::Tunnel` today; if a tunnel inbound ever reuses the
    // variant, probes need their own explicit marker.
    let metadata = meow_common::Metadata {
        network: meow_common::Network::Tcp,
        conn_type: meow_common::ConnType::Tunnel,
        host: parsed.host.as_str().into(),
        dst_port: parsed.port,
        ..Default::default()
    };

    let fut = probe_once(adapter, metadata, parsed, ranges);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(())) => {
            let delay = start.elapsed().as_millis().min(u16::MAX as u128) as u16;
            // Collapse sub-millisecond probes to 1 so callers can treat 0 as
            // the "probe did not complete" sentinel when they choose to.
            let delay = delay.max(1);
            debug!("{} URL test: {}ms", adapter.name(), delay);
            Ok(delay)
        }
        Ok(Err(e)) => {
            warn!("{} URL test transport error: {}", adapter.name(), e);
            Err(UrlTestError::Transport(e))
        }
        Err(_) => {
            warn!("{} URL test timeout after {:?}", adapter.name(), timeout);
            Err(UrlTestError::Timeout)
        }
    }
}

/// Probe a proxy and record the result in its [`ProxyHealth`].
///
/// On success the measured delay (ms) is recorded; on any failure `0` is
/// recorded so `last_delay == 0` and `alive() == false`.
pub async fn probe_and_record(
    proxy: &Arc<dyn Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, UrlTestError> {
    let _permit = global_delay_probe_limiter()
        .acquire()
        .await
        .expect("global delay probe semaphore is never closed");
    let adapter: &dyn ProxyAdapter = proxy.as_ref();
    let result = url_test(adapter, url, expected, timeout).await;
    match &result {
        Ok(d) => proxy.health().record_delay(*d),
        Err(_) => proxy.health().record_delay(0),
    }
    result
}

pub async fn probe_many_bounded(
    probes: Vec<(String, Arc<dyn Proxy + 'static>)>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    concurrency: usize,
) -> Vec<(String, u16)> {
    probe_many_bounded_detailed(probes, url, expected, timeout, concurrency)
        .await
        .into_iter()
        .map(|result| (result.name, result.delay))
        .collect()
}

pub async fn probe_many_bounded_detailed(
    probes: Vec<(String, Arc<dyn Proxy + 'static>)>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    concurrency: usize,
) -> Vec<NamedProbeResult> {
    let url = Arc::<str>::from(url.to_owned());
    let expected = expected.map(|s| Arc::<str>::from(s.to_owned()));
    let concurrency = concurrency.max(1);

    let mut probes = probes.into_iter();
    let mut pending = FuturesUnordered::new();
    for _ in 0..concurrency {
        let Some((name, proxy)) = probes.next() else {
            break;
        };
        pending.push(named_probe_future(
            name,
            proxy,
            Arc::clone(&url),
            expected.clone(),
            timeout,
        ));
    }

    let mut results = Vec::new();
    while let Some(result) = pending.next().await {
        results.push(result);
        if let Some((name, proxy)) = probes.next() {
            pending.push(named_probe_future(
                name,
                proxy,
                Arc::clone(&url),
                expected.clone(),
                timeout,
            ));
        }
    }

    results
}

fn named_probe_future(
    name: String,
    proxy: Arc<dyn Proxy + 'static>,
    url: Arc<str>,
    expected: Option<Arc<str>>,
    timeout: Duration,
) -> BoxFuture<'static, NamedProbeResult> {
    async move {
        match probe_and_record(&proxy, url.as_ref(), expected.as_deref(), timeout).await {
            Ok(delay) => NamedProbeResult {
                name,
                delay,
                error: None,
            },
            Err(error) => NamedProbeResult {
                name,
                delay: 0,
                error: Some(error),
            },
        }
    }
    .boxed()
}

fn global_delay_probe_limiter() -> &'static Semaphore {
    static LIMITER: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| Semaphore::new(GLOBAL_DELAY_PROBE_CONCURRENCY))
}

async fn probe_once(
    adapter: &dyn ProxyAdapter,
    metadata: meow_common::Metadata,
    parsed: ParsedUrl,
    ranges: Vec<(u16, u16)>,
) -> Result<(), String> {
    let conn = adapter
        .dial_tcp(&metadata)
        .await
        .map_err(|e| format!("dial: {e}"))?;

    if parsed.https {
        // Same TlsLayer the proxies dial with (BoringSSL by default). Both
        // backends memoise the TLS context per (alpn, skip_cert_verify), so
        // building a layer per probe is a hash lookup, not a root-store clone.
        let tls = TlsLayer::new(&TlsConfig::new(parsed.host.to_string()))
            .map_err(|e| format!("tls sni: {e}"))?;
        let tls = tls
            .connect(Box::new(conn))
            .await
            .map_err(|e| format!("tls: {e}"))?;
        send_get_and_check(tls, &parsed, &ranges).await
    } else {
        send_get_and_check(conn, &parsed, &ranges).await
    }
}

async fn send_get_and_check<S>(
    mut stream: S,
    parsed: &ParsedUrl,
    ranges: &[(u16, u16)],
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Host header includes the non-default port so virtual-hosted origins
    // route correctly; mirrors Go net/http's default behaviour.
    use std::io::Write as _;
    let mut buf = [0u8; 512];
    let default_port = if parsed.https { 443 } else { 80 };
    let mut cursor: &mut [u8] = &mut buf;
    if parsed.port == default_port {
        write!(
            cursor,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\n\
             User-Agent: clash.meta/{ver}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            path = parsed.path,
            host = parsed.host,
            ver = env!("CARGO_PKG_VERSION"),
        )
    } else {
        write!(
            cursor,
            "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\
             User-Agent: clash.meta/{ver}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            path = parsed.path,
            host = parsed.host,
            port = parsed.port,
            ver = env!("CARGO_PKG_VERSION"),
        )
    }
    .map_err(|_| "request too large for buffer".to_string())?;
    let remaining = cursor.len();
    let written = buf.len() - remaining;
    stream
        .write_all(&buf[..written])
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    let status = read_status_line(&mut stream).await?;
    trace!(status, "url_test: received status");
    if ranges.iter().any(|(lo, hi)| status >= *lo && status <= *hi) {
        Ok(())
    } else {
        Err(format!("unexpected status {status}"))
    }
}

async fn read_status_line<S>(stream: &mut S) -> Result<u16, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = [0u8; 1024];
    let mut len = 0usize;
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("eof before status line".into());
        }
        if len < buf.len() {
            buf[len] = byte[0];
            len += 1;
        }
        if buf[..len].ends_with(b"\r\n") || len >= buf.len() {
            break;
        }
    }
    let line = std::str::from_utf8(&buf[..len]).map_err(|_| "status line not utf-8".to_string())?;
    // HTTP/1.x status line: "HTTP/1.1 204 No Content\r\n"
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(format!("malformed status line: {line:?}"));
    }
    let code_str = parts
        .next()
        .ok_or_else(|| format!("missing status code: {line:?}"))?;
    code_str
        .parse::<u16>()
        .map_err(|_| format!("bad status code: {code_str:?}"))
}

#[derive(Debug, Clone)]
struct ParsedUrl {
    https: bool,
    host: SmolStr,
    port: u16,
    path: SmolStr,
}

impl ParsedUrl {
    fn parse(url: &str) -> Option<Self> {
        let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else {
            (false, url.strip_prefix("http://")?)
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return None;
        }
        // IPv6 literals wrap in `[...]`.
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let end = rest.find(']')?;
            let host = &rest[..end];
            let tail = &rest[end + 1..];
            let port = if let Some(p) = tail.strip_prefix(':') {
                p.parse().ok()?
            } else if https {
                443
            } else {
                80
            };
            (SmolStr::from(host), port)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            (SmolStr::from(h), p.parse().ok()?)
        } else {
            (SmolStr::from(authority), if https { 443 } else { 80 })
        };
        Some(Self {
            https,
            host,
            port,
            path: SmolStr::from(path),
        })
    }
}

/// Parse an `expected` query-param value into inclusive status-code ranges.
/// Empty / `None` defaults to `[200..=299]`, matching upstream.
fn parse_expected(spec: Option<&str>) -> Result<Vec<(u16, u16)>, String> {
    let s = spec.unwrap_or("").trim();
    if s.is_empty() {
        return Ok(vec![(200, 299)]);
    }
    let mut out = Vec::new();
    for piece in s.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = piece.split_once('-') {
            let lo: u16 = lo
                .trim()
                .parse()
                .map_err(|_| format!("expected: bad range {piece:?}"))?;
            let hi: u16 = hi
                .trim()
                .parse()
                .map_err(|_| format!("expected: bad range {piece:?}"))?;
            if lo > hi {
                return Err(format!("expected: inverted range {piece:?}"));
            }
            out.push((lo, hi));
        } else {
            let code: u16 = piece
                .parse()
                .map_err(|_| format!("expected: bad code {piece:?}"))?;
            out.push((code, code));
        }
    }
    if out.is_empty() {
        return Err("expected: empty".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_url_cases() {
        // (input, https, host, port, path)
        let accepted: &[(&str, bool, &str, u16, &str)] = &[
            (
                "https://www.gstatic.com/generate_204",
                true,
                "www.gstatic.com",
                443,
                "/generate_204",
            ),
            (
                "https://cp.cloudflare.com/generate_204",
                true,
                "cp.cloudflare.com",
                443,
                "/generate_204",
            ),
            ("http://example.com:8080", false, "example.com", 8080, "/"),
            ("http://[::1]:8080/x", false, "::1", 8080, "/x"),
        ];
        let rejected: &[&str] = &["ftp://x", "example.com"];

        // Collect instead of asserting inline so one bad input does not hide
        // the remaining cases.
        let mut failures = Vec::new();
        for (input, https, host, port, path) in accepted {
            match ParsedUrl::parse(input) {
                Some(p) => {
                    let got = (p.https, p.host.as_str(), p.port, p.path.as_str());
                    if got != (*https, *host, *port, *path) {
                        failures.push(format!(
                            "{input:?}: expected (https={https}, host={host:?}, port={port}, path={path:?}), got {got:?}"
                        ));
                    }
                }
                None => failures.push(format!("{input:?}: expected a parse, got None")),
            }
        }
        for input in rejected {
            if let Some(p) = ParsedUrl::parse(input) {
                failures.push(format!("{input:?}: expected None, got {p:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "ParsedUrl::parse mismatches:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn parse_expected_cases() {
        // (label, input, expected): expected is Some(ranges) when the input
        // must parse to exactly those ranges, None when it must be rejected.
        type Case = (
            &'static str,
            Option<&'static str>,
            Option<&'static [(u16, u16)]>,
        );
        let cases: &[Case] = &[
            ("default: None is 2xx", None, Some(&[(200, 299)])),
            (
                "default: empty string is 2xx",
                Some(""),
                Some(&[(200, 299)]),
            ),
            (
                "mixed list of codes and ranges",
                Some("200,204-206,301"),
                Some(&[(200, 200), (204, 206), (301, 301)]),
            ),
            ("inverted range is rejected", Some("300-200"), None),
            ("garbage is rejected", Some("abc"), None),
        ];

        // Every case runs even if an earlier one fails, so one bad input does
        // not hide the rest.
        let mut failures = Vec::new();
        for (label, input, expected) in cases {
            match (parse_expected(*input), expected) {
                (Ok(got), Some(want)) => {
                    if got.as_slice() != *want {
                        failures.push(format!(
                            "{label} ({input:?}): expected {want:?}, got {got:?}"
                        ));
                    }
                }
                (Err(_), None) => {}
                (Ok(got), None) => {
                    failures.push(format!(
                        "{label} ({input:?}): expected an error, got {got:?}"
                    ));
                }
                (Err(e), Some(want)) => {
                    failures.push(format!(
                        "{label} ({input:?}): expected {want:?}, got error {e:?}"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "parse_expected mismatches:\n{}",
            failures.join("\n")
        );
    }
}
