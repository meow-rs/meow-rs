use async_trait::async_trait;
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use meow_common::{
    AdapterType, ChainTarget, ChainVerdict, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn,
    ProxyPacketConn,
};
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::Transport as _;
use smol_str::SmolStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

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
    // `ConnType::Tunnel` today; `Metadata::internal` (#555) is the
    // explicit escape hatch `is_internal()` also honours, should a
    // tunnel inbound ever need to reuse the variant.
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

/// Chain probes per target per round stop once this many members reached
/// the target.
pub const CHAIN_PROBE_PASSES: usize = 3;

/// Chain probes per target per round at most. A target that is down itself
/// would otherwise cost a probe through every member, every round.
pub const CHAIN_PROBE_LIMIT: usize = 12;

/// What one [`probe_chain_target`] round found, by member name.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChainProbeReport {
    pub reached: Vec<String>,
    pub blocked: Vec<String>,
}

/// The active half of [`meow_common::chain_health`]: probe the
/// `dialer-proxy` chain to `target`, `[member, owner]` to `url`, through
/// the members of `group`, an automatic group, and record each verdict in
/// its chain health.
///
/// The group's own pick goes first, being the member the next front hop
/// takes, then the rest fastest first by the group's URL test, live ones
/// only. The round stops once [`CHAIN_PROBE_PASSES`] members reach the
/// target, or after [`CHAIN_PROBE_LIMIT`] probes. A member that is an
/// automatic group itself is skipped: it keeps its own verdicts. A failed
/// probe blocks the member for at least `hold`, which callers set past
/// their next round. When `owner` cannot run over a relayed stream, the
/// round records nothing.
pub async fn probe_chain_target(
    group: &Arc<dyn Proxy>,
    target: &ChainTarget,
    owner: &Arc<dyn Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    hold: Duration,
) -> ChainProbeReport {
    let (Some(health), Some(members)) = (group.chain_health(), group.member_proxies()) else {
        return ChainProbeReport::default();
    };
    let group_name = group.name();
    // Not a front hop, so the pick the group makes before its verdicts.
    let pick = group.unwrap_proxy(&Metadata::default(), false);
    let mut candidates: Vec<&Arc<dyn Proxy>> = members
        .iter()
        .filter(|m| {
            m.chain_health().is_none()
                && m.alive()
                && m.last_delay() > 0
                && m.name() != owner.name()
        })
        .collect();
    candidates.sort_by_key(|m| {
        let picked = pick.as_ref().is_some_and(|p| p.name() == m.name());
        (!picked, m.last_delay())
    });
    candidates.truncate(CHAIN_PROBE_LIMIT);

    let mut report = ChainProbeReport::default();
    let mut candidates = candidates.into_iter();
    while report.reached.len() < CHAIN_PROBE_PASSES {
        let batch: Vec<&Arc<dyn Proxy>> = candidates
            .by_ref()
            .take(CHAIN_PROBE_PASSES - report.reached.len())
            .collect();
        if batch.is_empty() {
            break;
        }
        let probes = batch.iter().map(|member| async move {
            let probe = ChainProbe::new(member, owner);
            let _permit = global_delay_probe_limiter()
                .acquire()
                .await
                .expect("global delay probe semaphore is never closed");
            let result = url_test(&probe, url, expected, timeout).await;
            (*member, result, probe.unsupported.load(Ordering::Relaxed))
        });
        for (member, result, unsupported) in futures::future::join_all(probes).await {
            if unsupported {
                debug!(
                    "proxy-group '{group_name}': cannot probe chains to {target}: '{}' does not \
                     run over a relayed stream",
                    owner.name()
                );
                return ChainProbeReport::default();
            }
            let name = member.name();
            if result.is_ok() {
                health.record_reached(target, name);
                report.reached.push(name.to_string());
                continue;
            }
            if let Some(length) = health.record_failed(target, name, ChainVerdict::Probe { hold }) {
                info!(
                    "proxy-group '{group_name}': member '{name}' cannot carry '{}' to {target}; \
                     skipping it for that target for {}s",
                    owner.name(),
                    length.as_secs()
                );
            }
            report.blocked.push(name.to_string());
        }
    }
    report
}

/// `[member, owner]` as one adapter for [`url_test`]. The relay dials the
/// owner's protocol fresh over a front hop through `member`, so no pooled
/// or multiplexed session of the owner's, which may ride another member,
/// answers for it.
struct ChainProbe {
    name: String,
    hops: [Arc<dyn Proxy>; 2],
    /// The relay refused the chain for a capability, not health.
    unsupported: AtomicBool,
    health: ProxyHealth,
}

impl ChainProbe {
    fn new(member: &Arc<dyn Proxy>, owner: &Arc<dyn Proxy>) -> Self {
        Self {
            name: format!("{} via {}", owner.name(), member.name()),
            hops: [Arc::clone(member), Arc::clone(owner)],
            unsupported: AtomicBool::new(false),
            health: ProxyHealth::new(),
        }
    }
}

#[async_trait]
impl ProxyAdapter for ChainProbe {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Relay
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> meow_common::Result<Box<dyn ProxyConn>> {
        let result = crate::group::relay::relay_tcp(&self.hops, metadata, None).await;
        if result.as_ref().is_err_and(MeowError::is_capability_error) {
            self.unsupported.store(true, Ordering::Relaxed);
        }
        result
    }

    async fn dial_udp(
        &self,
        _metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::UdpNotSupported)
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
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
        // CTL/space bytes would smuggle extra request lines or headers into
        // the probe request — reject before splitting authority/path. A
        // subscription-controlled `proxy-groups[].url` (or the `?url=` delay
        // endpoint) could otherwise write a raw `\r\n` onto the wire
        // (issue #648).
        if rest.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return None;
        }
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
        // CTL/whitespace bytes would inject raw request lines or headers
        // into the probe request (issue #648).
        let rejected: &[&str] = &[
            "ftp://x",
            "example.com",
            "http://victim/\r\nX-Injected: x",
            "http://victim/x y",
            "http://vic\ttim/",
            "http://vic\0tim/",
            "http://victim/\x0bz",
            "http://victim/\x7f",
            // CTL in the authority half, not just the path — these would
            // still parse (valid host + port) without the guard.
            "http://vic\ntim:8080/",
            "http://vic\rtim:8080/",
        ];

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

    mod chain_probe {
        use super::*;
        use crate::group::test_support::StreamProxy;

        const URL: &str = "http://probe.example/generate_204";

        fn daniel() -> Arc<dyn Proxy> {
            StreamProxy::new("daniel", "snell.example.com:8443")
        }

        fn fallback(members: &[Arc<StreamProxy>]) -> Arc<dyn Proxy> {
            let members = members.iter().map(|m| Arc::clone(m) as _).collect();
            Arc::new(crate::group::fallback::FallbackGroup::new("fast", members))
        }

        async fn probe(group: &Arc<dyn Proxy>, owner: &Arc<dyn Proxy>) -> ChainProbeReport {
            let target = ChainTarget::from_server_addr(owner.addr()).unwrap();
            probe_chain_target(
                group,
                &target,
                owner,
                URL,
                None,
                Duration::from_secs(5),
                Duration::from_secs(600),
            )
            .await
        }

        fn blocked(group: &Arc<dyn Proxy>, owner: &Arc<dyn Proxy>, member: &str) -> bool {
            let target = ChainTarget::from_server_addr(owner.addr()).unwrap();
            group.chain_health().unwrap().is_blocked(&target, member)
        }

        fn names(names: &[&str]) -> Vec<String> {
            names.iter().map(ToString::to_string).collect()
        }

        /// The member that passes the group's URL test but closes the
        /// chained outbound's port is blocked for that server at once;
        /// dead and unprobed members are not probed.
        #[tokio::test]
        async fn blocks_the_member_that_cannot_carry_the_chain() {
            let dead = StreamProxy::new("JP-01", "10.0.0.3:443");
            dead.set_delay(5);
            dead.health().set_alive(false);
            let unprobed = StreamProxy::new("US-01", "10.0.0.4:443");
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            clean.set_delay(20);
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            audited.set_delay(10);
            let group = fallback(&[
                Arc::clone(&dead),
                Arc::clone(&unprobed),
                Arc::clone(&clean),
                Arc::clone(&audited),
            ]);
            let owner = daniel();

            let report = probe(&group, &owner).await;
            assert_eq!(
                report,
                ChainProbeReport {
                    reached: names(&["HK-01"]),
                    blocked: names(&["SG-01"]),
                }
            );
            assert!(blocked(&group, &owner, "SG-01"));
            assert!(!blocked(&group, &owner, "HK-01"));
            assert_eq!((dead.dials(), unprobed.dials()), (0, 0));
        }

        /// A round stops at [`CHAIN_PROBE_PASSES`] members that reach the
        /// target: the group's pick, however slow, then the fastest.
        #[tokio::test]
        async fn probes_the_pick_then_the_fastest_until_enough_pass() {
            let members: Vec<Arc<StreamProxy>> = [50, 40, 10, 30, 20]
                .into_iter()
                .enumerate()
                .map(|(i, delay)| {
                    let member = StreamProxy::new(&format!("m{i}"), "10.0.0.1:443");
                    member.set_delay(delay);
                    member
                })
                .collect();
            let report = probe(&fallback(&members), &daniel()).await;
            assert_eq!(report.reached, names(&["m0", "m2", "m4"]));
            assert!(report.blocked.is_empty());
            let dials: Vec<usize> = members.iter().map(|m| m.dials()).collect();
            assert_eq!(dials, [1, 0, 1, 0, 1]);
        }

        /// Behind failures the round tries further members, up to
        /// [`CHAIN_PROBE_LIMIT`] probes in all.
        #[tokio::test]
        async fn a_target_no_member_reaches_costs_at_most_the_limit() {
            let members: Vec<Arc<StreamProxy>> = (1..=CHAIN_PROBE_LIMIT as u16 + 3)
                .map(|i| {
                    let member = StreamProxy::auditing(&format!("m{i}"), "10.0.0.1:443", 8443);
                    member.set_delay(i);
                    member
                })
                .collect();
            let report = probe(&fallback(&members), &daniel()).await;
            assert!(report.reached.is_empty());
            assert_eq!(report.blocked.len(), CHAIN_PROBE_LIMIT);
            let dials: usize = members.iter().map(|m| m.dials()).sum();
            assert_eq!(dials, CHAIN_PROBE_LIMIT);
        }

        /// An outbound that cannot run over a relayed stream says nothing
        /// about the members: the round records nothing.
        #[tokio::test]
        async fn an_owner_without_relay_support_records_nothing() {
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            audited.set_delay(10);
            let group = fallback(&[audited]);
            let owner: Arc<dyn Proxy> = StreamProxy::without_relay("hy2", "hy2.example.com:8443");
            assert_eq!(probe(&group, &owner).await, ChainProbeReport::default());
            assert!(!blocked(&group, &owner, "SG-01"));
        }
    }
}
