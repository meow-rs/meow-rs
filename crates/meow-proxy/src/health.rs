use async_trait::async_trait;
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use meow_common::logbook::{self, Level};
use meow_common::{
    failure_reason, AdapterType, ChainTarget, ChainVerdict, MeowError, Metadata, Proxy,
    ProxyAdapter, ProxyConn, ProxyPacketConn,
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

/// Members a sweep's [chain check](sweep_members) tries at most before it
/// takes a chained outbound for down, besides the one the outbound's own
/// probe went through.
pub const CHAIN_CHECK_LIMIT: usize = 3;

/// What one chain probe round found, by member name.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChainProbeReport {
    /// Members that reached the target, in the order tried, with the
    /// probe's delay.
    pub reached: Vec<(String, u16)>,
    /// Members that failed while another reached the target. Each is
    /// blocked for it now.
    pub blocked: Vec<String>,
    /// Members that failed in a round where none reached the target. The
    /// target is the likelier fault, so their records stand.
    pub failed: Vec<String>,
}

/// The active half of [`meow_common::chain_health`]: probe the
/// `dialer-proxy` chain to `target`, `[member, owner]` to `url`, through
/// the members of `group`, an automatic group, and record the verdicts in
/// its chain health.
///
/// Members go in the order front hops come back to them: the target's
/// carrier, then the group's own pick, then the rest fastest first by the
/// group's URL test, live ones only. A url-test group keeps front hops on
/// the carrier; a fallback group returns them to its own pick once that is
/// not blocked. Members blocked for the target are probed too, so a
/// passing probe clears a block early. The round stops once
/// [`CHAIN_PROBE_PASSES`] members reach the target, or after
/// [`CHAIN_PROBE_LIMIT`] probes. A member that is an automatic group itself
/// is skipped: it keeps its own verdicts. When some member reaches the
/// target, each one that failed is blocked for at least `hold`, which
/// callers set past their next round; one blocked already stays blocked at
/// its backoff level. When none reaches it, the target is the likelier
/// fault and the round records nothing. When `owner` cannot run over a
/// relayed stream, the round records nothing either. A carrier the group
/// has down hands over to the first member that reached the target.
pub async fn probe_chain_target(
    group: &Arc<dyn Proxy>,
    target: &ChainTarget,
    owner: &Arc<dyn Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    hold: Duration,
) -> ChainProbeReport {
    let round = ChainRound {
        group,
        target,
        owner,
        url,
        expected,
        timeout,
        hold,
        tried: None,
    };
    round
        .run(CHAIN_PROBE_PASSES, CHAIN_PROBE_LIMIT, false)
        .await
        .unwrap_or_default()
}

/// One round of chain probes; see [`probe_chain_target`].
struct ChainRound<'a> {
    group: &'a Arc<dyn Proxy>,
    target: &'a ChainTarget,
    owner: &'a Arc<dyn Proxy>,
    url: &'a str,
    expected: Option<&'a str>,
    timeout: Duration,
    hold: Duration,
    /// The member a probe of the owner itself went through and failed, for
    /// the reason given: a check counts it as tried rather than dialling it
    /// again.
    tried: Option<(&'a str, &'static str)>,
}

impl ChainRound<'_> {
    /// Probe until `passes` members reach the target, `limit` probes at
    /// most, besides the member [tried](Self::tried) already. A `check`
    /// skips members blocked for the target and tries members the group has
    /// not probed yet, after the rest: the first sweep of the group
    /// dialling the owner may run before the front group's. `None` when the
    /// group keeps no verdicts or the owner cannot be relayed.
    async fn run(&self, passes: usize, limit: usize, check: bool) -> Option<ChainProbeReport> {
        let health = self.group.chain_health()?;
        let members = self.group.member_proxies()?;
        let group_name = self.group.name();
        let owner = self.owner;
        let carrier = health.carrier(self.target);
        // Not a front hop, so the pick the group makes before its verdicts.
        let pick = self.group.unwrap_proxy(&Metadata::default(), false);
        let tried = self.tried.and_then(|(name, reason)| {
            let member = members
                .iter()
                .find(|m| m.name() == name && m.chain_health().is_none())?;
            Some((member, reason))
        });
        let mut candidates: Vec<&Arc<dyn Proxy>> = members
            .iter()
            .filter(|m| {
                m.chain_health().is_none()
                    && m.alive()
                    && (check || m.last_delay() > 0)
                    && m.name() != owner.name()
                    && !(check && health.is_blocked(self.target, m.name()))
                    && tried.is_none_or(|(tried, _)| tried.name() != m.name())
            })
            .collect();
        candidates.sort_by_key(|m| {
            let rank = if carrier.as_deref() == Some(m.name()) {
                0
            } else if pick.as_ref().is_some_and(|p| p.name() == m.name()) {
                1
            } else {
                2
            };
            (rank, m.last_delay() == 0, m.last_delay())
        });
        candidates.truncate(limit);

        let mut reached: Vec<(&Arc<dyn Proxy>, u16)> = Vec::new();
        let mut failed: Vec<(&Arc<dyn Proxy>, &'static str)> = tried.into_iter().collect();
        let mut candidates = candidates.into_iter();
        while reached.len() < passes {
            let batch: Vec<&Arc<dyn Proxy>> =
                candidates.by_ref().take(passes - reached.len()).collect();
            if batch.is_empty() {
                break;
            }
            let probes = batch.iter().map(|member| async move {
                let probe = ChainProbe::new(member, owner);
                let _permit = global_delay_probe_limiter()
                    .acquire()
                    .await
                    .expect("global delay probe semaphore is never closed");
                let result = url_test(&probe, self.url, self.expected, self.timeout).await;
                (*member, result, probe.unsupported.load(Ordering::Relaxed))
            });
            for (member, result, unsupported) in futures::future::join_all(probes).await {
                if unsupported {
                    debug!(
                        "proxy-group '{group_name}': cannot probe chains to {}: '{}' does not \
                         run over a relayed stream",
                        self.target,
                        owner.name()
                    );
                    return None;
                }
                match result {
                    Ok(delay) => reached.push((member, delay)),
                    Err(error) => failed.push((member, url_test_reason(&error))),
                }
            }
        }

        let name = |m: &Arc<dyn Proxy>| m.name().to_owned();
        if reached.is_empty() {
            return Some(ChainProbeReport {
                failed: failed.iter().map(|(m, _)| name(m)).collect(),
                ..ChainProbeReport::default()
            });
        }
        // Failures first: a carrier blocked here hands over to the first
        // member that reached the target.
        for (member, reason) in &failed {
            let probe = ChainVerdict::Probe { hold: self.hold };
            if let Some(length) = health.record_failed(self.target, member.name(), probe, reason) {
                info!(
                    "proxy-group '{group_name}': member '{}' cannot carry '{}' to {} \
                     ({reason}); skipping it for that target for {}s",
                    member.name(),
                    owner.name(),
                    self.target,
                    length.as_secs()
                );
            }
        }
        // So does a carrier that is no longer a live member of the group.
        let mut carrier_down = carrier
            .as_deref()
            .is_some_and(|carrier| !members.iter().any(|m| m.name() == carrier && m.alive()));
        for (member, _) in &reached {
            let down = std::mem::take(&mut carrier_down);
            if let Some(change) = health.record_probe_reached(self.target, member.name(), down) {
                crate::group::carrier_changed(group_name, self.target, member.name(), &change);
            }
        }
        Some(ChainProbeReport {
            reached: reached.iter().map(|(m, delay)| (name(m), *delay)).collect(),
            blocked: failed.iter().map(|(m, _)| name(m)).collect(),
            failed: Vec::new(),
        })
    }
}

/// [`failure_reason`] of a [`url_test`] error.
fn url_test_reason(error: &UrlTestError) -> &'static str {
    match error {
        UrlTestError::Timeout => "timed out",
        UrlTestError::Transport(e) => failure_reason(e),
    }
}

/// One member's outcome in [`sweep_members`].
#[derive(Debug)]
pub struct SweptMember {
    pub name: String,
    /// The delay recorded, `0` when the member is down.
    pub delay: u16,
    /// Why the member is down.
    pub reason: Option<String>,
}

/// Probe the members of a group being swept and record each delay, like
/// [`probe_many_bounded`], with one difference for a chained outbound: an
/// outbound that dials through an automatic group among `fronts`, with its
/// health check failing. The failure may be the front hop's, not the
/// outbound's, so before it is recorded the chain is checked through other
/// members of that group: the member the failed probe went through counts
/// as tried, then come the target's carrier and the members front hops
/// return to, [`CHAIN_CHECK_LIMIT`] at most, each over a fresh connection,
/// skipping members blocked for the outbound's server. When one reaches
/// the server, the outbound is up: its delay through that member is
/// recorded, each member that failed is blocked for that server for at
/// least `hold`, and the member that reached it becomes the carrier unless
/// the target's carrier still works. Only when none does is the outbound
/// down. Without this, one
/// failed probe through a bad front member took the outbound out of its
/// group until the next sweep.
///
/// A failed check is recorded in the logbook (`dialer-proxy.check`), and
/// so is the next passing health check of that outbound.
pub async fn sweep_members(
    members: Vec<(String, Arc<dyn Proxy>)>,
    fronts: &[Arc<dyn Proxy>],
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    concurrency: usize,
    hold: Duration,
) -> Vec<SweptMember> {
    let sweeps: Vec<_> = members
        .into_iter()
        .map(|(name, proxy)| sweep_member(name, proxy, fronts, url, expected, timeout, hold))
        .collect();
    futures::stream::iter(sweeps)
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await
}

/// [`sweep_members`] for one member.
async fn sweep_member(
    name: String,
    proxy: Arc<dyn Proxy>,
    fronts: &[Arc<dyn Proxy>],
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    hold: Duration,
) -> SweptMember {
    let (result, front_pick) = {
        let _permit = global_delay_probe_limiter()
            .acquire()
            .await
            .expect("global delay probe semaphore is never closed");
        crate::group::watch_member_dial(url_test(proxy.as_ref(), url, expected, timeout)).await
    };
    let (delay, reason) = match result {
        Ok(delay) => (delay, None),
        Err(error) => {
            let reason = url_test_reason(&error);
            match chain_of(fronts, &name) {
                Some((front, target)) => {
                    let round = ChainRound {
                        group: front,
                        target: &target,
                        owner: &proxy,
                        url,
                        expected,
                        timeout,
                        hold,
                        tried: front_pick.as_ref().map(|member| (member.name(), reason)),
                    };
                    check_chain(&round, &name, reason).await
                }
                None => (0, Some(reason.to_owned())),
            }
        }
    };
    proxy.health().record_delay(delay);
    if delay > 0 && logbook::failing(logbook::kind::DIALER_PROXY_CHECK, &name) {
        logbook::event(
            logbook::kind::DIALER_PROXY_CHECK,
            Level::Info,
            format!("'{name}' passes its health check again"),
        )
        .subject(name.as_str())
        .record();
    }
    SweptMember {
        name,
        delay,
        reason,
    }
}

/// The automatic group among `fronts` that `owner` dials through, with the
/// server it dials. The owner's own failed probe has just noted it there.
fn chain_of<'a>(
    fronts: &'a [Arc<dyn Proxy>],
    owner: &str,
) -> Option<(&'a Arc<dyn Proxy>, ChainTarget)> {
    fronts.iter().find_map(|front| {
        let (target, _) = front
            .chain_health()?
            .targets()
            .into_iter()
            .find(|(_, owners)| owners.iter().any(|o| o == owner))?;
        Some((front, target))
    })
}

/// [`sweep_members`]' chain check of `owner`, whose health check failed
/// for `reason`: the delay to record and, when that is `0`, why.
async fn check_chain(
    round: &ChainRound<'_>,
    owner: &str,
    reason: &'static str,
) -> (u16, Option<String>) {
    let front = round.group.name();
    let report = round.run(1, CHAIN_CHECK_LIMIT, true).await;
    let Some(report) = report else {
        return (0, Some(reason.to_owned()));
    };
    if let Some((member, delay)) = report.reached.first() {
        info!(
            "health-check: '{owner}' failed its probe ({reason}) but reached its server \
             through '{member}' of '{front}'; keeping it up"
        );
        return (*delay, None);
    }
    let tried = report.failed.len();
    let why = if tried == 0 {
        format!("{reason}; no member of '{front}' left to try")
    } else {
        format!("{reason}; unreachable through {tried} members of '{front}' tried")
    };
    warn!("health-check: '{owner}' is down: {why}");
    let message = if tried == 0 {
        format!("'{owner}' failed its health check ({reason}) and no member of '{front}' was left to try")
    } else {
        format!(
            "'{owner}' failed its health check ({reason}) through every member of '{front}' tried: {}",
            quoted(&report.failed)
        )
    };
    logbook::event(logbook::kind::DIALER_PROXY_CHECK, Level::Error, message)
        .subject(owner)
        .field("group", front)
        .field("reason", reason)
        .field("tried", tried)
        .coalesce()
        .record();
    (0, Some(why))
}

/// `'a', 'b', 'c'`.
fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ")
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
        use crate::group::test_support::{StreamProxy, TestLogbook};
        use meow_common::logbook::kind;

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

        fn reached(report: &ChainProbeReport) -> Vec<String> {
            report
                .reached
                .iter()
                .map(|(name, _)| name.clone())
                .collect()
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
            assert_eq!(reached(&report), names(&["HK-01"]));
            assert_eq!(report.blocked, names(&["SG-01"]));
            assert!(report.failed.is_empty());
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
            assert_eq!(reached(&report), names(&["m0", "m2", "m4"]));
            assert!(report.blocked.is_empty());
            let dials: Vec<usize> = members.iter().map(|m| m.dials()).collect();
            assert_eq!(dials, [1, 0, 1, 0, 1]);
        }

        /// Behind failures the round tries further members, up to
        /// [`CHAIN_PROBE_LIMIT`] probes in all. When none reaches the
        /// target, the target is the likelier fault: no member is blocked.
        #[tokio::test]
        async fn a_target_no_member_reaches_costs_at_most_the_limit() {
            let members: Vec<Arc<StreamProxy>> = (1..=CHAIN_PROBE_LIMIT as u16 + 3)
                .map(|i| {
                    let member = StreamProxy::auditing(&format!("m{i}"), "10.0.0.1:443", 8443);
                    member.set_delay(i);
                    member
                })
                .collect();
            let group = fallback(&members);
            let owner = daniel();
            let report = probe(&group, &owner).await;
            assert!(report.reached.is_empty());
            assert!(report.blocked.is_empty());
            assert_eq!(report.failed.len(), CHAIN_PROBE_LIMIT);
            let dials: usize = members.iter().map(|m| m.dials()).sum();
            assert_eq!(dials, CHAIN_PROBE_LIMIT);
            assert!(!blocked(&group, &owner, "m1"));
        }

        /// The target's carrier goes first, ahead of the group's pick, and
        /// stays the carrier while it reaches the target.
        #[tokio::test]
        async fn probes_the_carrier_first() {
            let members: Vec<Arc<StreamProxy>> = [10, 20, 30, 40]
                .into_iter()
                .enumerate()
                .map(|(i, delay)| {
                    let member = StreamProxy::new(&format!("m{i}"), "10.0.0.1:443");
                    member.set_delay(delay);
                    member
                })
                .collect();
            let group = fallback(&members);
            let owner = daniel();
            let target = ChainTarget::from_server_addr(owner.addr()).unwrap();
            let health = group.chain_health().unwrap();
            health.record_reached(&target, "m3");
            let report = probe(&group, &owner).await;
            assert_eq!(reached(&report), names(&["m3", "m0", "m1"]));
            assert_eq!(health.carrier(&target).as_deref(), Some("m3"));
        }

        /// A carrier that fails a round is blocked, and the first member
        /// that reached the target takes over, which the logbook records
        /// under the chained outbound with the reason.
        #[tokio::test]
        async fn a_blocked_carrier_hands_over_to_the_first_that_reached() {
            let book = TestLogbook::install();
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            audited.set_delay(10);
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            clean.set_delay(20);
            let group = fallback(&[Arc::clone(&audited), Arc::clone(&clean)]);
            let owner: Arc<dyn Proxy> = StreamProxy::new("carrier-owner", "snell.example.com:8443");
            let target = ChainTarget::from_server_addr(owner.addr()).unwrap();
            let health = group.chain_health().unwrap();
            health.note_owner(&target, "carrier-owner");
            health.record_reached(&target, "SG-01");

            let report = probe(&group, &owner).await;
            assert_eq!(report.blocked, names(&["SG-01"]));
            assert_eq!(health.carrier(&target).as_deref(), Some("HK-01"));
            let entries = book.entries("carrier-owner");
            assert_eq!(entries.len(), 1, "{entries:?}");
            assert_eq!(entries[0].kind, kind::DIALER_PROXY_SWITCH);
            assert_eq!(
                entries[0].message,
                "'carrier-owner' now dials through 'HK-01' of 'fast' (was 'SG-01': closed \
                 before any reply)"
            );
        }

        /// A blocked member is probed again each round, so a passing probe
        /// can clear it early. Failing again, it stays blocked at the level
        /// it reached: the backoff does not grow by the round.
        #[tokio::test]
        async fn a_blocked_member_is_probed_again_without_growing_its_block() {
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            audited.set_delay(10);
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            clean.set_delay(20);
            let group = fallback(&[Arc::clone(&audited), Arc::clone(&clean)]);
            let owner = daniel();
            let target = ChainTarget::from_server_addr(owner.addr()).unwrap();
            for _ in 0..4 {
                let report = probe(&group, &owner).await;
                assert_eq!(report.blocked, names(&["SG-01"]));
            }
            assert_eq!(audited.dials(), 4);
            let blocks = group.chain_health().unwrap().blocked(&target);
            assert_eq!(blocks.len(), 1);
            assert!(
                blocks[0].1 <= Duration::from_secs(600),
                "held for the round's hold, not a longer backoff: {blocks:?}"
            );
        }

        /// A carrier its group has down hands over to the first member that
        /// reaches the target, which the logbook records with the reason.
        #[tokio::test]
        async fn a_carrier_that_is_down_hands_over_to_the_first_that_reached() {
            let book = TestLogbook::install();
            let gone = StreamProxy::new("SG-01", "10.0.0.1:443");
            gone.set_delay(10);
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            clean.set_delay(20);
            let group = fallback(&[Arc::clone(&gone), Arc::clone(&clean)]);
            let owner: Arc<dyn Proxy> = StreamProxy::new("down-owner", "snell.example.com:8443");
            let target = ChainTarget::from_server_addr(owner.addr()).unwrap();
            let health = group.chain_health().unwrap();
            health.note_owner(&target, "down-owner");
            health.record_reached(&target, "SG-01");
            gone.health().set_alive(false);

            let report = probe(&group, &owner).await;
            assert_eq!(reached(&report), names(&["HK-01"]));
            assert_eq!(health.carrier(&target).as_deref(), Some("HK-01"));
            let entries = book.entries("down-owner");
            assert_eq!(entries.len(), 1, "{entries:?}");
            assert_eq!(
                entries[0].message,
                "'down-owner' now dials through 'HK-01' of 'fast' (was 'SG-01': down)"
            );
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

        /// A url-test `fast` of `members`, published for a chained `owner`
        /// at `snell.example.com:8443` that dials through it. The registry
        /// must outlive the dials.
        fn chained(
            owner: &str,
            members: &[&Arc<StreamProxy>],
        ) -> (Arc<dyn Proxy>, Arc<dyn Proxy>, crate::dialer::ProxyRegistry) {
            let members = members.iter().map(|m| Arc::clone(m) as _).collect();
            chained_via(
                Arc::new(crate::group::urltest::UrlTestGroup::new("fast", members, 0)),
                owner,
            )
        }

        /// [`chained`] through `fast`, a group named so.
        fn chained_via(
            fast: Arc<dyn Proxy>,
            owner: &str,
        ) -> (Arc<dyn Proxy>, Arc<dyn Proxy>, crate::dialer::ProxyRegistry) {
            use crate::group::test_support::{registry_of, ChainedProxy};
            let registry = registry_of(&[&fast]);
            let owner: Arc<dyn Proxy> =
                ChainedProxy::new(owner, "snell.example.com:8443", "fast", &registry);
            (fast, owner, registry)
        }

        async fn sweep(fast: &Arc<dyn Proxy>, member: &Arc<dyn Proxy>) -> SweptMember {
            let mut swept = sweep_members(
                vec![(member.name().to_owned(), Arc::clone(member))],
                std::slice::from_ref(fast),
                URL,
                None,
                Duration::from_secs(5),
                4,
                Duration::from_secs(600),
            )
            .await;
            assert_eq!(swept.len(), 1);
            swept.pop().unwrap()
        }

        /// The chained outbound's own probe goes through the fastest
        /// member, which closes its port. Before taking the outbound for
        /// down, the sweep checks the chain through the next member, which
        /// reaches the server: the outbound stays up, the member that
        /// failed is blocked for the server, and the one that reached it
        /// carries its chains.
        #[tokio::test]
        async fn a_chained_outbound_stays_up_when_another_front_member_reaches_it() {
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            audited.set_delay(10);
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            clean.set_delay(20);
            let (fast, owner, _registry) = chained("daniel", &[&audited, &clean]);

            let swept = sweep(&fast, &owner).await;
            assert!(swept.delay > 0, "{swept:?}");
            assert_eq!(swept.reason, None);
            assert!(owner.alive());
            assert!(blocked(&fast, &owner, "SG-01"));
            let target = ChainTarget::from_server_addr(owner.addr()).unwrap();
            let health = fast.chain_health().unwrap();
            assert_eq!(health.carrier(&target).as_deref(), Some("HK-01"));
            assert_eq!(
                (audited.dials(), clean.dials()),
                (1, 1),
                "the check counts the member the outbound's probe went through as tried"
            );

            // The next probe goes straight through the carrier.
            assert!(sweep(&fast, &owner).await.delay > 0);
            assert_eq!((audited.dials(), clean.dials()), (1, 2));
        }

        /// A fallback front returns to its first member once that member is
        /// no longer blocked, ahead of the carrier. When the outbound's
        /// probe fails through it, the check counts it as tried, reaches
        /// the server through the carrier, and blocks the member, which the
        /// next dial would otherwise take again.
        #[tokio::test]
        async fn a_fallback_front_blocks_the_member_it_returned_to() {
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            audited.set_delay(10);
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            clean.set_delay(20);
            let (fast, owner, _registry) = chained_via(
                fallback(&[Arc::clone(&audited), Arc::clone(&clean)]),
                "daniel-fb",
            );
            let target = ChainTarget::from_server_addr(owner.addr()).unwrap();
            let health = fast.chain_health().unwrap();
            health.record_reached(&target, "HK-01");

            let swept = sweep(&fast, &owner).await;
            assert!(swept.delay > 0, "{swept:?}");
            assert!(blocked(&fast, &owner, "SG-01"));
            assert_eq!((audited.dials(), clean.dials()), (1, 1));
            assert_eq!(health.carrier(&target).as_deref(), Some("HK-01"));
        }

        /// The first sweep of the group dialling the outbound may run
        /// before the front group's: a check then tries members not probed
        /// yet.
        #[tokio::test]
        async fn a_check_before_the_front_groups_first_sweep_tries_unprobed_members() {
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            let (fast, owner, _registry) = chained("daniel-early", &[&audited, &clean]);
            let swept = sweep(&fast, &owner).await;
            assert!(swept.delay > 0, "{swept:?}");
            assert!(blocked(&fast, &owner, "SG-01"));
        }

        /// When no member reaches the server, the outbound is down: the
        /// logbook says so once, blaming no member, and records the next
        /// passing check.
        #[tokio::test]
        async fn a_chained_outbound_no_member_reaches_is_down() {
            let book = TestLogbook::install();
            let first = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            first.set_delay(10);
            let second = StreamProxy::auditing("JP-01", "10.0.0.3:443", 8443);
            second.set_delay(30);
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            clean.set_delay(50);
            clean.health().set_alive(false);
            let (fast, owner, _registry) = chained("daniel-down", &[&first, &second, &clean]);

            let swept = sweep(&fast, &owner).await;
            assert_eq!(swept.delay, 0);
            assert_eq!(
                swept.reason.as_deref(),
                Some("closed before any reply; unreachable through 2 members of 'fast' tried")
            );
            assert!(!owner.alive());
            assert!(!blocked(&fast, &owner, "SG-01"));
            assert!(!blocked(&fast, &owner, "JP-01"));
            let entries = book.entries("daniel-down");
            assert_eq!(entries.len(), 1, "{entries:?}");
            assert_eq!(
                (entries[0].kind.as_str(), entries[0].level),
                (kind::DIALER_PROXY_CHECK, Level::Error)
            );
            assert_eq!(
                entries[0].message,
                "'daniel-down' failed its health check (closed before any reply) through every \
                 member of 'fast' tried: 'SG-01', 'JP-01'"
            );

            // A member that reaches the server comes back as the fastest.
            clean.set_delay(5);
            assert!(sweep(&fast, &owner).await.delay > 0);
            let entries = book.entries("daniel-down");
            assert_eq!(entries.len(), 2, "{entries:?}");
            assert_eq!(
                (entries[0].level, entries[0].message.as_str()),
                (Level::Info, "'daniel-down' passes its health check again")
            );
        }

        /// A member that dials through no automatic group fails as before.
        #[tokio::test]
        async fn an_unchained_member_fails_without_a_check() {
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 80);
            audited.set_delay(10);
            let fast = fallback(&[]);
            let member: Arc<dyn Proxy> = Arc::clone(&audited) as _;
            let swept = sweep(&fast, &member).await;
            assert_eq!(swept.delay, 0);
            assert_eq!(swept.reason.as_deref(), Some("closed before any reply"));
            assert!(!member.alive());
            assert_eq!(audited.dials(), 1);
        }
    }
}
