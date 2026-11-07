use async_trait::async_trait;
use futures::{future::BoxFuture, FutureExt, Stream, StreamExt, TryStreamExt};
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

static UNIFIED_DELAY: AtomicBool = AtomicBool::new(false);

/// mihomo `unified-delay`: when set, a probe sends a second request on the
/// same warm connection and reports only that one, so the delay is one
/// round trip through the proxy rather than dial + handshakes + request.
/// Applied on every config load. A probe batch ([`sweep_members`],
/// [`probe_stream_bounded`], [`probe_chain_target`], [`diagnose_chain`])
/// reads it once at entry, so a `PUT /configs` flipping the flag mid-sweep
/// cannot mix dial-inclusive and warm-only measurements inside one
/// ranking — a tighter bound than upstream, which loads it per probe.
pub fn set_unified_delay(on: bool) {
    UNIFIED_DELAY.store(on, Ordering::Relaxed);
}

/// The live `unified-delay` setting.
pub fn unified_delay() -> bool {
    UNIFIED_DELAY.load(Ordering::Relaxed)
}

/// Probe a proxy by dialing the target, issuing an HTTP/1.1 `GET` (two
/// keep-alive `HEAD`s under `unified-delay`, timing the second), and
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
    url_test_with(adapter, url, expected, timeout, unified_delay()).await
}

/// [`url_test`] under the caller's `unified-delay` mode, so a probe batch
/// can read the flag once at entry and keep every probe in it comparable.
async fn url_test_with(
    adapter: &dyn ProxyAdapter,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    unified: bool,
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

    // The deadline the warm second request of a unified probe is bounded
    // by, so a peer that accepts one HEAD but never answers the next is
    // the slow node mihomo reports, not a `Timeout`.
    let deadline = tokio::time::Instant::now() + timeout;
    let fut = probe_once(adapter, metadata, parsed, ranges, unified, deadline);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(second)) => {
            let delay = second
                .unwrap_or(start)
                .elapsed()
                .as_millis()
                .min(u16::MAX as u128) as u16;
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
    probe_and_record_with(proxy, url, expected, timeout, unified_delay()).await
}

/// [`probe_and_record`] under the caller's `unified-delay` mode; see
/// [`url_test_with`].
async fn probe_and_record_with(
    proxy: &Arc<dyn Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    unified: bool,
) -> Result<u16, UrlTestError> {
    let _permit = global_delay_probe_limiter()
        .acquire()
        .await
        .expect("global delay probe semaphore is never closed");
    let adapter: &dyn ProxyAdapter = proxy.as_ref();
    let result = url_test_with(adapter, url, expected, timeout, unified).await;
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
    probe_stream_bounded(probes, url, expected, timeout, concurrency)
        .collect()
        .await
}

/// [`probe_many_bounded_detailed`] as a stream: each result as soon as its
/// probe ends, with at most `concurrency` probes running. A caller with a
/// deadline of its own keeps what arrived by then; dropping the stream
/// cancels the probes still running, and those record nothing.
pub fn probe_stream_bounded(
    probes: Vec<(String, Arc<dyn Proxy + 'static>)>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    concurrency: usize,
) -> impl Stream<Item = NamedProbeResult> + Send + 'static {
    let url = Arc::<str>::from(url.to_owned());
    let expected = expected.map(|s| Arc::<str>::from(s.to_owned()));
    // One `unified-delay` mode for the whole batch: a `PUT /configs`
    // flipping the flag mid-stream must not mix dial-inclusive and
    // warm-only measurements the caller compares.
    let unified = unified_delay();
    futures::stream::iter(probes)
        .map(move |(name, proxy)| {
            named_probe_future(
                name,
                proxy,
                Arc::clone(&url),
                expected.clone(),
                timeout,
                unified,
            )
        })
        .buffer_unordered(concurrency.max(1))
}

fn named_probe_future(
    name: String,
    proxy: Arc<dyn Proxy + 'static>,
    url: Arc<str>,
    expected: Option<Arc<str>>,
    timeout: Duration,
    unified: bool,
) -> BoxFuture<'static, NamedProbeResult> {
    async move {
        match probe_and_record_with(&proxy, url.as_ref(), expected.as_deref(), timeout, unified)
            .await
        {
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
/// probe went through. Dials take the server for down after as many
/// members ([`meow_common::chain_health::BLAMED_MEMBERS`]).
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
///
/// An `owner` that is down when a member reaches the target is up again:
/// the probe ran its protocol end to end, so its delay through the first
/// member that reached the target is recorded, and the groups that hold it
/// take it back now rather than at their next health check. The logbook
/// records the recovery (`dialer-proxy.check`).
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
        unified: unified_delay(),
        tried: None,
    };
    let report = round
        .run(CHAIN_PROBE_PASSES, CHAIN_PROBE_LIMIT, false)
        .await
        .unwrap_or_default();
    if let Some((member, delay)) = report.reached.first() {
        if !owner.alive() {
            revive_owner(group.name(), owner, member, *delay);
        }
    }
    report
}

/// `owner`, a chained outbound that is down, reached its server through
/// `member` of `group` in a chain probe: record the probe's `delay` as its
/// own, which marks it alive, and the recovery in the logbook. Only a
/// health check marked it down, or its dial failures did, and either
/// recorded that in the logbook.
fn revive_owner(group: &str, owner: &Arc<dyn Proxy>, member: &str, delay: u16) {
    let name = owner.name();
    info!(
        "proxy-group '{group}': chained outbound '{name}' reached its server through \
         '{member}' in a chain probe; marking it alive"
    );
    owner.health().record_delay(delay);
    record_passing(name, Some((group, member)));
}

/// Record that `name`, a chained outbound, passes again, when its latest
/// `dialer-proxy.check` entry is a failure: its own health check passed, or
/// a chain probe through `via`, a group and its member, reached its server.
fn record_passing(name: &str, via: Option<(&str, &str)>) {
    if !logbook::failing(logbook::kind::DIALER_PROXY_CHECK, name) {
        return;
    }
    let message = match via {
        Some((group, member)) => {
            format!("'{name}' reaches its server again through '{member}' of '{group}'")
        }
        None => format!("'{name}' passes its health check again"),
    };
    let mut event =
        logbook::event(logbook::kind::DIALER_PROXY_CHECK, Level::Info, message).subject(name);
    if let Some((group, member)) = via {
        event = event.field("group", group).field("member", member);
    }
    event.record();
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
    /// The `unified-delay` mode the caller's batch runs under.
    unified: bool,
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
                let result =
                    url_test_with(&probe, self.url, self.expected, self.timeout, self.unified)
                        .await;
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
    // One `unified-delay` mode for the whole sweep: a `PUT /configs`
    // flipping the flag mid-sweep must not mix dial-inclusive and
    // warm-only measurements the group ranks members by.
    let unified = unified_delay();
    let sweeps: Vec<_> = members
        .into_iter()
        .map(|(name, proxy)| {
            sweep_member(name, proxy, fronts, url, expected, timeout, hold, unified)
        })
        .collect();
    futures::stream::iter(sweeps)
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await
}

/// [`sweep_members`] for one member.
#[allow(
    clippy::too_many_arguments,
    reason = "one probe spec per member; a struct would only rename the same values"
)]
async fn sweep_member(
    name: String,
    proxy: Arc<dyn Proxy>,
    fronts: &[Arc<dyn Proxy>],
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    hold: Duration,
    unified: bool,
) -> SweptMember {
    let (result, front_pick) = {
        let _permit = global_delay_probe_limiter()
            .acquire()
            .await
            .expect("global delay probe semaphore is never closed");
        crate::group::watch_member_dial(url_test_with(
            proxy.as_ref(),
            url,
            expected,
            timeout,
            unified,
        ))
        .await
    };
    let delay = match result {
        Ok(delay) => delay,
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
                        unified,
                        tried: front_pick.as_ref().map(|member| (member.name(), reason)),
                    };
                    check_chain(&round, &name, reason).await
                }
                None => 0,
            }
        }
    };
    proxy.health().record_delay(delay);
    if delay > 0 {
        record_passing(&name, None);
    }
    SweptMember { name, delay }
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
/// for `reason`: the delay to record.
async fn check_chain(round: &ChainRound<'_>, owner: &str, reason: &'static str) -> u16 {
    let front = round.group.name();
    let report = round.run(1, CHAIN_CHECK_LIMIT, true).await;
    let Some(report) = report else {
        return 0;
    };
    if let Some((member, delay)) = report.reached.first() {
        info!(
            "health-check: '{owner}' failed its probe ({reason}) but reached its server \
             through '{member}' of '{front}'; keeping it up"
        );
        return *delay;
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
    0
}

/// What [`diagnose_chain`] found for one member: whether it can carry a
/// chained outbound to its server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainDiagnosis {
    /// The chain through the member reached the URL in `delay` ms.
    /// `member_delay` is the member's own probe, `None` when that failed.
    Reached {
        delay: u16,
        member_delay: Option<u16>,
    },
    /// The member reaches the URL on its own, and another member carried
    /// the chain, but not this one: it cannot carry the chain, the mark of
    /// a front that audits the outbound's server.
    Failed {
        member_delay: u16,
        reason: &'static str,
    },
    /// The member reaches the URL on its own but not the chain, and no
    /// member carried the chain: the outbound's server is the likelier
    /// fault, so this says nothing about the member.
    Inconclusive {
        member_delay: u16,
        reason: &'static str,
    },
    /// Neither the chain nor the member alone reached the URL: whether it
    /// can carry the chain is unknown.
    Down { reason: &'static str },
    /// Not probed: the member is a group, or the outbound itself.
    Skipped { reason: &'static str },
}

/// One member's [`ChainDiagnosis`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberDiagnosis {
    pub name: String,
    pub diagnosis: ChainDiagnosis,
}

/// Why [`diagnose_chain`] probed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainDiagnosisError {
    /// The outbound is a group, not a proxy.
    Group,
    /// The outbound has no server to dial, like DIRECT.
    NoServer,
    /// The outbound cannot run over a relayed stream, like hysteria2. This
    /// shows once a member reaches its server: while none does, the
    /// members read as [`ChainDiagnosis::Down`] or
    /// [`ChainDiagnosis::Inconclusive`].
    Unsupported,
}

/// Probe `owner` as a chained outbound through each of `members`, the
/// front hop forced to that member whether or not `owner` sets a
/// `dialer-proxy`: `[member, owner]` to `url`, and the member alone, both
/// over fresh connections. Results keep the order of `members`, probed
/// [`GROUP_DELAY_CONCURRENCY`] at a time.
///
/// A diagnosis only: no delay, chain verdict or logbook entry is recorded,
/// and `owner` is never registered anywhere.
pub async fn diagnose_chain(
    owner: &Arc<dyn Proxy>,
    members: &[Arc<dyn Proxy>],
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<Vec<MemberDiagnosis>, ChainDiagnosisError> {
    if owner.member_proxies().is_some() {
        return Err(ChainDiagnosisError::Group);
    }
    if ChainTarget::from_server_addr(owner.addr()).is_none() {
        return Err(ChainDiagnosisError::NoServer);
    }
    let unified = unified_delay();
    let probes: Vec<_> = members
        .iter()
        .map(|member| diagnose_member(owner, member, url, expected, timeout, unified))
        .collect();
    let mut found: Vec<MemberDiagnosis> = futures::stream::iter(probes)
        .buffered(GROUP_DELAY_CONCURRENCY)
        .try_collect()
        .await?;
    let reached = found
        .iter()
        .any(|m| matches!(m.diagnosis, ChainDiagnosis::Reached { .. }));
    if !reached {
        for member in &mut found {
            if let ChainDiagnosis::Failed {
                member_delay,
                reason,
            } = member.diagnosis
            {
                member.diagnosis = ChainDiagnosis::Inconclusive {
                    member_delay,
                    reason,
                };
            }
        }
    }
    Ok(found)
}

/// [`diagnose_chain`] for one member. A member that fails the chain is
/// [`ChainDiagnosis::Failed`] until the caller sees whether any reached.
async fn diagnose_member(
    owner: &Arc<dyn Proxy>,
    member: &Arc<dyn Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    unified: bool,
) -> Result<MemberDiagnosis, ChainDiagnosisError> {
    let name = member.name().to_owned();
    let skipped = if member.member_proxies().is_some() {
        Some("a group")
    } else if member.name() == owner.name() {
        Some("the proxy itself")
    } else {
        None
    };
    if let Some(reason) = skipped {
        return Ok(MemberDiagnosis {
            name,
            diagnosis: ChainDiagnosis::Skipped { reason },
        });
    }
    let probe = ChainProbe::new(member, owner);
    let (chain, alone) = tokio::join!(
        limited_url_test(&probe, url, expected, timeout, unified),
        limited_url_test(member.as_ref(), url, expected, timeout, unified),
    );
    if probe.unsupported.load(Ordering::Relaxed) {
        return Err(ChainDiagnosisError::Unsupported);
    }
    let diagnosis = match (chain, alone) {
        (Ok(delay), alone) => ChainDiagnosis::Reached {
            delay,
            member_delay: alone.ok(),
        },
        (Err(error), Ok(member_delay)) => ChainDiagnosis::Failed {
            member_delay,
            reason: url_test_reason(&error),
        },
        (Err(_), Err(error)) => ChainDiagnosis::Down {
            reason: url_test_reason(&error),
        },
    };
    Ok(MemberDiagnosis { name, diagnosis })
}

/// [`url_test`] under the global probe limit, recording nothing.
async fn limited_url_test(
    adapter: &dyn ProxyAdapter,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    unified: bool,
) -> Result<u16, UrlTestError> {
    let _permit = global_delay_probe_limiter()
        .acquire()
        .await
        .expect("global delay probe semaphore is never closed");
    url_test_with(adapter, url, expected, timeout, unified).await
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
    unified: bool,
    deadline: tokio::time::Instant,
) -> Result<Option<Instant>, String> {
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
        check_maybe_twice(tls, &parsed, &ranges, unified, deadline).await
    } else {
        check_maybe_twice(conn, &parsed, &ranges, unified, deadline).await
    }
}

/// One `GET` — or, for `unified-delay`, two keep-alive `HEAD`s as mihomo
/// sends them, returning when the second started. As in mihomo's
/// `URLTest`, the first response gates on transport only and the status
/// check applies to the response kept: the second's, or — when the second
/// request fails in transport or runs past `deadline` — the first's,
/// with the full measurement.
async fn check_maybe_twice<S>(
    mut stream: S,
    parsed: &ParsedUrl,
    ranges: &[(u16, u16)],
    unified: bool,
    deadline: tokio::time::Instant,
) -> Result<Option<Instant>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if !unified {
        return send_get_and_check(stream, parsed, ranges)
            .await
            .map(|()| None);
    }
    send_request(&mut stream, parsed, "HEAD", "keep-alive").await?;
    let first = read_head(&mut stream).await?;
    // As in mihomo's `URLTest`: the second timer starts once the first
    // response is fully read, before the warm request goes on the wire.
    let second = Instant::now();
    let warm = async {
        match send_request(&mut stream, parsed, "HEAD", "close").await {
            Err(e) => Err(format!("second request not sent: {e}")),
            Ok(()) => read_status_line(&mut stream)
                .await
                .map_err(|e| format!("second response not read: {e}")),
        }
    };
    // A second exchange that hangs — write wedged on a half-open
    // connection, or a peer that accepts the HEAD but never answers —
    // must not escalate to the probe's outer `timeout`, which would
    // report a dead node. mihomo lets the second `client.Do` fail with
    // the context deadline and keeps the first measurement, so the warm
    // exchange is bounded by the same deadline here. `Timeout::poll`
    // polls the inner future before checking its own deadline: when this
    // `timeout_at` fires, the fallback below completes synchronously
    // inside that poll and the outer `timeout` sees `Ready`, not
    // `Elapsed` — no same-deadline race.
    let warm = tokio::time::timeout_at(deadline, warm)
        .await
        .unwrap_or_else(|_| {
            Err("second request did not complete within the probe deadline".to_string())
        });
    match warm {
        Ok(status) => check_status(status, ranges).map(|()| Some(second)),
        Err(e) => {
            warn!("url_test: unified-delay {e}; falling back to the first measurement");
            check_status(first, ranges).map(|()| None)
        }
    }
}

fn check_status(status: u16, ranges: &[(u16, u16)]) -> Result<(), String> {
    trace!(status, "url_test: received status");
    if ranges.iter().any(|(lo, hi)| status >= *lo && status <= *hi) {
        Ok(())
    } else {
        Err(format!("unexpected status {status}"))
    }
}

/// Read a response head (status line + headers) and return its status; a
/// `HEAD` response has no body, so the connection is then ready for the
/// next request.
async fn read_head<S>(stream: &mut S) -> Result<u16, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let status = read_status_line(stream).await?;
    // Status line consumed with its CRLF; the head ends at an empty line.
    let mut tail = [0u8; 4];
    tail[2..].copy_from_slice(b"\r\n");
    let mut byte = [0u8; 1];
    for _ in 0..16 * 1024 {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("eof in response headers".into());
        }
        tail.rotate_left(1);
        tail[3] = byte[0];
        if &tail == b"\r\n\r\n" {
            return Ok(status);
        }
    }
    Err("response headers too large".into())
}

async fn send_get_and_check<S>(
    mut stream: S,
    parsed: &ParsedUrl,
    ranges: &[(u16, u16)],
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    send_request(&mut stream, parsed, "GET", "close").await?;
    check_status(read_status_line(&mut stream).await?, ranges)
}

async fn send_request<S>(
    stream: &mut S,
    parsed: &ParsedUrl,
    method: &str,
    connection: &str,
) -> Result<(), String>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    // Host header includes the non-default port so virtual-hosted origins
    // route correctly; mirrors Go net/http's default behaviour. Built in a
    // Vec so no fixed cap splits the two request shapes — the unified-delay
    // HEAD with `keep-alive` runs 6 bytes longer than the plain GET.
    use std::io::Write as _;
    let default_port = if parsed.https { 443 } else { 80 };
    let mut buf = Vec::with_capacity(512);
    if parsed.port == default_port {
        write!(
            buf,
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\n\
             User-Agent: clash.meta/{ver}\r\nAccept: */*\r\nConnection: {connection}\r\n\r\n",
            path = parsed.path,
            host = parsed.host,
            ver = env!("CARGO_PKG_VERSION"),
        )
    } else {
        write!(
            buf,
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\
             User-Agent: clash.meta/{ver}\r\nAccept: */*\r\nConnection: {connection}\r\n\r\n",
            path = parsed.path,
            host = parsed.host,
            port = parsed.port,
            ver = env!("CARGO_PKG_VERSION"),
        )
    }
    .expect("writing to a Vec cannot fail");
    stream
        .write_all(&buf)
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))
}

async fn read_status_line<S>(stream: &mut S) -> Result<u16, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = [0u8; 1024];
    // `len` counts bytes past `buf` too: a status line longer than the
    // buffer keeps draining to its CRLF so a following `read_head` still
    // finds the headers where they start; `buf` then holds the truncated
    // line, whose version and code are intact.
    let mut len = 0usize;
    let mut byte = [0u8; 1];
    let mut prev = 0u8;
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
        }
        len += 1;
        let end = prev == b'\r' && byte[0] == b'\n';
        prev = byte[0];
        if end {
            break;
        }
        if len > buf.len() + 16 * 1024 {
            return Err("status line too long".into());
        }
    }
    let line = std::str::from_utf8(&buf[..len.min(buf.len())])
        .map_err(|_| "status line not utf-8".to_string())?;
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

/// Validate an `expected-status` spec at config load (mihomo fails the
/// provider build on a bad one rather than every probe at run time).
/// `pub` for that one caller — `meow-config`'s provider build; it lives
/// in `meow-proxy` because the spec it validates is this crate's
/// probe-domain syntax.
///
/// Note the shared `parse_expected` default under it: an empty spec is
/// `[200..=299]` — a deliberate divergence from upstream, where empty
/// parses to `nil` ranges matching *any* status. It feeds the
/// group/delay probe paths too, so changing it for providers alone
/// would flip them all.
pub fn validate_expected_status(spec: &str) -> Result<(), String> {
    parse_expected(Some(spec)).map(drop)
}

/// Codes and `lo-hi` ranges separated by `,` or `/` (mihomo's spelling,
/// `200/302`), or `*` for any status.
fn parse_expected(spec: Option<&str>) -> Result<Vec<(u16, u16)>, String> {
    let s = spec.unwrap_or("").trim();
    if s.is_empty() {
        return Ok(vec![(200, 299)]);
    }
    if s == "*" {
        return Ok(vec![(0, u16::MAX)]);
    }
    let mut out = Vec::new();
    for piece in s.split([',', '/']) {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        if piece == "*" {
            return Err(
                "expected: `*` (any status) must stand alone — it cannot be combined \
                 in a list"
                    .into(),
            );
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

    /// `unified-delay`: two HEADs on one connection, the first keep-alive;
    /// the second's start is reported. A peer closing after the first
    /// keeps the full measurement (None), as mihomo does.
    /// The status that decides is the kept response's: first 503 then 204
    /// is alive, first 204 then 302 is dead (mihomo `URLTest`).
    #[tokio::test]
    async fn unified_delay_checks_the_kept_response_status() {
        let parsed = ParsedUrl::parse("http://probe.test/generate_204").unwrap();
        let ranges = parse_expected(None).unwrap();
        for (first, second, alive) in [("503", "204", true), ("204", "302", false)] {
            let (client, mut server) = tokio::io::duplex(4096);
            let srv = tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                let mut answered = 0;
                while answered < 2 {
                    let n = server.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                    let requests = seen.windows(4).filter(|w| w == b"\r\n\r\n").count();
                    while answered < requests {
                        let code = if answered == 0 { first } else { second };
                        let resp = format!("HTTP/1.1 {code} X\r\nServer: t\r\n\r\n");
                        server.write_all(resp.as_bytes()).await.unwrap();
                        answered += 1;
                    }
                }
            });
            let got = check_maybe_twice(
                client,
                &parsed,
                &ranges,
                true,
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await;
            srv.await.unwrap();
            assert_eq!(got.is_ok(), alive, "{first} then {second}");
        }
    }

    #[tokio::test]
    async fn unified_delay_times_the_second_request_on_a_warm_connection() {
        let parsed = ParsedUrl::parse("http://probe.test/generate_204").unwrap();
        let ranges = parse_expected(None).unwrap();
        for second_answered in [true, false] {
            // When `second_answered` is false the server still reads the
            // second HEAD before hanging up, so the client sees the
            // exchange as a failed response, not a dead connection.
            let cap = if second_answered { 2 } else { 1 };
            let (client, mut server) = tokio::io::duplex(4096);
            let srv = tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                let mut answered = 0;
                loop {
                    let n = server.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                    let requests = seen.windows(4).filter(|w| w == b"\r\n\r\n").count();
                    while answered < requests.min(cap) {
                        server
                            .write_all(b"HTTP/1.1 204 No Content\r\nServer: t\r\n\r\n")
                            .await
                            .unwrap();
                        answered += 1;
                    }
                    if requests >= 2 {
                        break;
                    }
                }
                String::from_utf8(seen).unwrap()
            });
            let warm = check_maybe_twice(
                client,
                &parsed,
                &ranges,
                true,
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect("first request passes");
            let seen = srv.await.unwrap();
            assert!(seen.starts_with("HEAD /generate_204 HTTP/1.1\r\n"));
            // Both HEADs go out in either branch; `second_answered=false`
            // fails on the second response, not on sending it.
            assert_eq!(seen.matches("HEAD ").count(), 2, "{seen}");
            assert_eq!(seen.matches("Connection: keep-alive").count(), 1);
            assert_eq!(seen.matches("Connection: close").count(), 1);
            assert_eq!(warm.is_some(), second_answered);
        }
    }

    /// A second HEAD the server receives but never answers falls back to
    /// the first measurement at the probe deadline — mihomo's behaviour
    /// on a hijacked test URL that cannot take repeated HEADs: the node
    /// reports alive with the deadline's delay, not `Timeout`.
    #[tokio::test]
    async fn unified_delay_a_silent_second_exchange_keeps_the_first_measurement() {
        // `Serves::Everything` answers one REPLY then only drains reads:
        // the second HEAD goes out and is never answered while the
        // connection stays open.
        let proxy = crate::group::test_support::StreamProxy::new("slow", "probe.test:80");
        let timeout = Duration::from_millis(200);
        let delay = url_test_with(
            proxy.as_ref(),
            "http://probe.test/generate_204",
            None,
            timeout,
            true,
        )
        .await
        .expect("the first measurement keeps the node alive");
        assert!(
            delay as u64 >= timeout.as_millis() as u64
                && (delay as u64) < timeout.as_millis() as u64 + 1000,
            "delay ≈ the probe deadline, got {delay}"
        );
    }

    /// A status line longer than the read buffer drains to its CRLF
    /// instead of leaving the tail for `read_head` to scan as headers:
    /// the truncated copy still carries version and code, and the head
    /// after it lines up.
    #[tokio::test]
    async fn over_long_status_line_drains_to_its_crlf() {
        let reason = "x".repeat(4 * 1024);
        let wire = format!("HTTP/1.1 204 {reason}\r\nServer: t\r\n\r\n");
        let (mut client, mut server) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move {
            server.write_all(wire.as_bytes()).await.unwrap();
        });
        let status = read_head(&mut client).await.expect("status parses");
        srv.await.unwrap();
        assert_eq!(status, 204);
    }

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
                "mihomo slash list",
                Some("200/204"),
                Some(&[(200, 200), (204, 204)]),
            ),
            ("mihomo any", Some("*"), Some(&[(0, u16::MAX)])),
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
            ("star in a list is rejected", Some("*,200"), None),
            ("star in a slash list is rejected", Some("200/*"), None),
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

    /// `*` mixed into a list must not surface as an opaque `bad code "*"` —
    /// the error names the standalone-only rule.
    #[test]
    fn expected_status_star_in_list_explains_standalone() {
        let err = validate_expected_status("*,200").unwrap_err();
        assert!(err.contains("stand alone"), "unexpected: {err}");
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
        /// An outbound that is down comes back up as soon as a chain probe
        /// reaches its server: its delay through the first member that
        /// reached it is recorded, and so is the recovery, in the logbook.
        #[tokio::test]
        async fn a_probe_that_reaches_the_server_revives_a_down_owner() {
            let book = TestLogbook::install();
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            audited.set_delay(10);
            let clean = StreamProxy::new("HK-01", "10.0.0.2:443");
            clean.set_delay(20);
            let group = fallback(&[Arc::clone(&audited), Arc::clone(&clean)]);
            let owner: Arc<dyn Proxy> =
                StreamProxy::new("daniel-revived", "snell.example.com:8443");
            owner.health().record_delay(0);
            logbook::event(kind::DIALER_PROXY_CHECK, Level::Error, "down")
                .subject("daniel-revived")
                .record();

            let report = probe(&group, &owner).await;
            assert_eq!(reached(&report), names(&["HK-01"]));
            assert!(owner.alive());
            assert_eq!(owner.last_delay(), report.reached[0].1);
            let entries = book.entries("daniel-revived");
            assert_eq!(entries.len(), 2, "{entries:?}");
            assert_eq!(
                (entries[0].kind.as_str(), entries[0].level),
                (kind::DIALER_PROXY_CHECK, Level::Info)
            );
            assert_eq!(
                entries[0].message,
                "'daniel-revived' reaches its server again through 'HK-01' of 'fast'"
            );
            let fields = &entries[0].fields;
            assert_eq!(
                (&fields["group"], &fields["member"]),
                (&"fast".into(), &"HK-01".into())
            );

            // Up already, the next probe leaves its delay to its own checks.
            let history = owner.delay_history().len();
            probe(&group, &owner).await;
            assert_eq!(owner.delay_history().len(), history);
            assert_eq!(book.entries("daniel-revived").len(), 2);
        }

        /// A probe that reaches no member leaves a down outbound down.
        #[tokio::test]
        async fn a_probe_that_reaches_no_member_leaves_a_down_owner_down() {
            let audited = StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443);
            audited.set_delay(10);
            let group = fallback(&[audited]);
            let owner = daniel();
            owner.health().record_delay(0);
            assert!(probe(&group, &owner).await.reached.is_empty());
            assert!(!owner.alive());
        }

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
            assert!(!member.alive());
            assert_eq!(audited.dials(), 1);
        }
    }

    mod diagnose {
        use super::*;
        use crate::group::test_support::StreamProxy;
        use meow_common::chain_health::CLOSED_BEFORE_REPLY;

        const URL: &str = "http://probe.example/generate_204";

        fn daniel() -> Arc<dyn Proxy> {
            StreamProxy::new("daniel", "snell.example.com:8443")
        }

        async fn diagnose(
            owner: &Arc<dyn Proxy>,
            members: &[Arc<dyn Proxy>],
        ) -> Result<Vec<MemberDiagnosis>, ChainDiagnosisError> {
            diagnose_chain(owner, members, URL, None, Duration::from_millis(300)).await
        }

        /// Each member gets its own verdict, in the group's order: the
        /// audited one fails the chain while working alone, the one that
        /// fails alone is down, and groups and the outbound itself are not
        /// probed. Nothing is recorded.
        #[tokio::test]
        async fn tells_audited_members_from_clean_and_down_ones() {
            let clean = StreamProxy::new("HK-01", "10.0.0.1:443");
            let audited = StreamProxy::auditing("SG-01", "10.0.0.2:443", 8443);
            let down = StreamProxy::hanging("JP-01", "10.0.0.3:443");
            // Closes the probe URL's port only: it carries the chain.
            let lone = StreamProxy::auditing("US-01", "10.0.0.4:443", 80);
            let group: Arc<dyn Proxy> = Arc::new(crate::group::selector::SelectorGroup::new(
                "Auto",
                vec![Arc::clone(&clean) as _],
            ));
            let owner = daniel();
            let members: Vec<Arc<dyn Proxy>> = vec![
                Arc::clone(&clean) as _,
                Arc::clone(&audited) as _,
                Arc::clone(&down) as _,
                Arc::clone(&lone) as _,
                group,
                Arc::clone(&owner),
            ];

            let found = diagnose(&owner, &members).await.unwrap();
            let names: Vec<&str> = found.iter().map(|m| m.name.as_str()).collect();
            assert_eq!(
                names,
                ["HK-01", "SG-01", "JP-01", "US-01", "Auto", "daniel"]
            );
            let diagnoses: Vec<ChainDiagnosis> = found.iter().map(|m| m.diagnosis).collect();
            assert!(
                matches!(
                    diagnoses[0],
                    ChainDiagnosis::Reached {
                        delay: 1..,
                        member_delay: Some(1..)
                    }
                ),
                "{diagnoses:?}"
            );
            assert!(
                matches!(
                    diagnoses[1],
                    ChainDiagnosis::Failed {
                        member_delay: 1..,
                        reason: CLOSED_BEFORE_REPLY
                    }
                ),
                "{diagnoses:?}"
            );
            assert_eq!(
                diagnoses[2],
                ChainDiagnosis::Down {
                    reason: "timed out"
                }
            );
            assert!(
                matches!(
                    diagnoses[3],
                    ChainDiagnosis::Reached {
                        member_delay: None,
                        ..
                    }
                ),
                "{diagnoses:?}"
            );
            assert_eq!(
                diagnoses[4..],
                [
                    ChainDiagnosis::Skipped { reason: "a group" },
                    ChainDiagnosis::Skipped {
                        reason: "the proxy itself"
                    },
                ]
            );

            // Each probed member was dialled twice, alone and as the front
            // hop, and kept no delay or verdict.
            let members = [&clean, &audited, &down, &lone];
            for member in members {
                assert_eq!(member.dials(), 2, "{}", member.name());
                assert_eq!(member.last_delay(), 0, "{}", member.name());
                assert!(member.alive(), "{}", member.name());
            }
            assert_eq!(owner.last_delay(), 0);
            assert!(owner.alive());
        }

        /// When no member carries the chain, the outbound's server is the
        /// likelier fault: members that work alone are inconclusive, not
        /// failed.
        #[tokio::test]
        async fn no_member_reaching_the_server_fails_none() {
            let members: Vec<Arc<dyn Proxy>> = vec![
                StreamProxy::auditing("SG-01", "10.0.0.1:443", 8443),
                StreamProxy::auditing("SG-02", "10.0.0.2:443", 8443),
                StreamProxy::hanging("JP-01", "10.0.0.3:443"),
            ];
            let found = diagnose(&daniel(), &members).await.unwrap();
            let diagnoses: Vec<ChainDiagnosis> = found.iter().map(|m| m.diagnosis).collect();
            assert!(
                matches!(
                    diagnoses[..],
                    [
                        ChainDiagnosis::Inconclusive {
                            reason: CLOSED_BEFORE_REPLY,
                            ..
                        },
                        ChainDiagnosis::Inconclusive {
                            reason: CLOSED_BEFORE_REPLY,
                            ..
                        },
                        ChainDiagnosis::Down {
                            reason: "timed out"
                        },
                    ]
                ),
                "{diagnoses:?}"
            );
        }

        /// An outbound that cannot run over a relayed stream, a group, and
        /// one with no server are refused whole.
        #[tokio::test]
        async fn refuses_outbounds_it_cannot_chain() {
            let members: Vec<Arc<dyn Proxy>> = vec![StreamProxy::new("HK-01", "10.0.0.1:443")];
            let hy2: Arc<dyn Proxy> = StreamProxy::without_relay("hy2", "hy2.example.com:8443");
            assert_eq!(
                diagnose(&hy2, &members).await,
                Err(ChainDiagnosisError::Unsupported)
            );
            let group: Arc<dyn Proxy> = Arc::new(crate::group::selector::SelectorGroup::new(
                "Auto",
                members.clone(),
            ));
            assert_eq!(
                diagnose(&group, &members).await,
                Err(ChainDiagnosisError::Group)
            );
            let serverless: Arc<dyn Proxy> = StreamProxy::new("DIRECT", "");
            assert_eq!(
                diagnose(&serverless, &members).await,
                Err(ChainDiagnosisError::NoServer)
            );
        }
    }
}
