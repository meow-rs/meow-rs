use meow_common::atomic::AtomicU;
use meow_common::logbook::{self, Level};
use meow_common::{
    conn_note, failure_reason, AdapterType, Blame, CarrierChange, ChainHealth, ChainTarget,
    ChainVerdict, MeowError, Metadata, Proxy, ProxyConn, CLOSED_BEFORE_REPLY,
};
use parking_lot::Mutex;
use smol_str::SmolStr;
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info};

/// Lock-free traffic-use generation shared by automatic proxy groups. A lazy
/// health-check loop remembers the last generation it probed and sleeps until
/// another dial increments this counter.
pub(super) struct UsageTracker(AtomicU);

impl UsageTracker {
    pub(super) fn new() -> Self {
        Self(AtomicU::new(0))
    }

    pub(super) fn touch(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a use, but only for real user traffic.
    ///
    /// Health-check probes dial with [`meow_common::ConnType::Tunnel`] — an internal
    /// marker set by `health::url_test` (no production dialer uses the
    /// variant) — and housekeeping traffic (provider/geodata/subscription
    /// fetches, DNS-via-proxy) carries [`Metadata::internal`].  Counting
    /// either as uses would defeat lazy mode: a parent group's periodic
    /// probes or a background refresh would mark a lazy child as used and
    /// keep its own probe loop awake forever without any real traffic.
    pub(super) fn touch_user_traffic(&self, metadata: &Metadata) {
        if metadata.is_internal() {
            return;
        }
        self.touch();
    }

    pub(super) fn generation(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; u32→u64 widening on targets without 64-bit atomics"
        )]
        u64::from(self.0.load(Ordering::Relaxed))
    }
}

/// Escalation threshold and window, matching mihomo's `GroupBase` defaults
/// (`maxFailedTimes = 5`, `testTimeout = 5000` ms —
/// adapter/outboundgroup/groupbase.go).
///
/// Note the window interaction with the dial deadline: each
/// `with_dial_timeout` failure burns the full 5s dial budget, so *serial*
/// deadline-timeout dials land >5s apart and always reset the streak —
/// a serially-blackholed member is dead-marked only by the probe sweep.
/// Concurrent dials sharing an expiry do escalate. Same shape as
/// upstream's `failedTime` window.
const DIAL_FAILURE_THRESHOLD: u32 = 5;
const DIAL_FAILURE_WINDOW: Duration = Duration::from_secs(5);

/// Dial-failure escalation state shared by the automatic groups, modeled on
/// mihomo's `GroupBase.onDialFailed`.
///
/// mihomo's terminal action on escalation is to force a provider health
/// check. The group layer here cannot trigger probes (the health-check loop
/// lives in meow-app), so the local equivalent is to mark the failed member
/// dead: routing stops selecting it immediately. A member is revived by the
/// next scheduled group probe — guaranteed to run for a lazy group, because
/// a dial bumps the usage generation. The sweep resolves members through
/// `member_proxies()`, so provider-slot members are probed and revived too
/// (issue #543).
///
/// Unlike [`UsageTracker::touch_user_traffic`], failure recording does NOT
/// skip internal traffic (mihomo's `onDialFailed` ignores the touch flag
/// the same way): a failed dial is real evidence the member is down,
/// regardless of who asked.  The asymmetry is deliberate — housekeeping
/// traffic neither keeps a lazy group awake nor hides a dead member.
pub(super) struct DialFailureTracker {
    state: Mutex<DialFailureState>,
}

struct DialFailureState {
    count: u32,
    first_at: Option<Instant>,
}

impl DialFailureTracker {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(DialFailureState {
                count: 0,
                first_at: None,
            }),
        }
    }

    /// mihomo resets the failure streak on dial success
    /// (`GroupBase.onDialSuccess`).
    pub(super) fn on_success(&self) {
        let mut state = self.state.lock();
        state.count = 0;
        state.first_at = None;
    }

    /// Record a failed dial; returns `true` when the failure should escalate
    /// (the caller then marks the failed member dead).
    pub(super) fn on_failure(&self, err: &MeowError) -> bool {
        // mihomo ignores C.ErrNotSupport failures outright; meow splits that
        // sentinel into `NotSupported` and `UdpNotSupported`. Both describe a
        // member's capabilities, not its health (e.g. a relay chain without
        // UDP support), so neither may count toward marking a member dead.
        // The check walks `RelayHopFailed` chains and io-boundary
        // reconstitution — a refusal from hop N of a chained front is the
        // same permanent property (issue #663).
        //
        // Local resource exhaustion (EMFILE/ENFILE/ENOBUFS/ENOMEM at any
        // hop depth, errno preserved across the dialer io boundary) is
        // likewise not evidence the member is down: dead-marking a healthy
        // node for local fd pressure blackholes the group until the next
        // probe sweep (issue #668).
        //
        // Exemption trade-off: a member that fails *permanently* with an
        // exempt class (e.g. a hop that can never carry UDP) keeps being
        // selected — fail-fast each dial — until the health sweep's
        // `record_delay(0)` marks it dead (or the delay API does). Groups
        // with probing disabled (`interval: 0`) have no such bound, the
        // same shape mihomo's ErrNotSupport exemption already carries.
        if err.is_capability_error() || err.is_local_resource_error() {
            return false;
        }
        // mihomo escalates immediately on "connection refused" and leaves the
        // streak untouched.
        if err.to_string().contains("refused") {
            return true;
        }
        let mut state = self.state.lock();
        state.count += 1;
        if state.count == 1 {
            state.first_at = Some(Instant::now());
            return false;
        }
        if state
            .first_at
            .is_some_and(|at| Instant::now().duration_since(at) > DIAL_FAILURE_WINDOW)
        {
            // mihomo drops the stale streak and starts a fresh window.
            state.count = 0;
            state.first_at = None;
            return false;
        }
        if state.count >= DIAL_FAILURE_THRESHOLD {
            state.count = 0;
            state.first_at = None;
            return true;
        }
        false
    }
}

/// Shared dial-failure policy for automatic groups, mirroring the exemptions
/// in mihomo's `GroupBase.onDialFailed`: adapter types whose dial errors
/// describe the *target* (Direct / Reject family) are never tracked, and
/// everything else escalates through the group's [`DialFailureTracker`].
/// Escalation marks the failed member dead — see [`DialFailureTracker`] for
/// why this stands in for mihomo's forced health check.
pub(super) fn record_dial_failure(
    group_name: &str,
    tracker: &DialFailureTracker,
    member: &Arc<dyn Proxy>,
    err: &MeowError,
) {
    if matches!(
        member.adapter_type(),
        AdapterType::Direct
            | AdapterType::Compatible
            | AdapterType::Reject
            | AdapterType::RejectDrop
            | AdapterType::Pass
            | AdapterType::PassRule
    ) {
        return;
    }
    if tracker.on_failure(err) {
        debug!(
            "proxy-group '{group_name}': marking member '{}' dead after repeated dial failures",
            member.name()
        );
        member.health().set_alive(false);
    }
}

tokio::task_local! {
    /// Set while an automatic group dials a member, and while the health
    /// check probes one ([`watch_member_dial`]): what the groups and
    /// `dialer-proxy` front hops on the member's path report.
    static MEMBER_DIAL: MemberDial;
}

#[derive(Default)]
struct MemberDial {
    /// A front hop on the path failed for its own member
    /// ([`front_hop_failed`]).
    front_failed: Cell<bool>,
    /// The member the last group dialled on the path took. A front hop
    /// that fails reads it ([`last_pick_is`]).
    pick: RefCell<Option<Arc<dyn Proxy>>>,
}

/// The current dial failed at a `dialer-proxy` front hop, for the front
/// group's member: it failed to dial while the group still has another
/// live member, or it closed the chain before any reply, or let the dial's
/// deadline pass with the request unanswered, without having carried a
/// chain to that server before. The front group counts the member; the
/// group dialling the chained outbound does not count the outbound. A front
/// member refusing a connection would otherwise mark a healthy chained
/// outbound dead at once, and a burst of connections through a member that
/// drops the server's port would mark it dead after five
/// (`DialFailureTracker`). A carrier that fails still counts against the
/// outbound: a member known to reach the server failing is the likelier
/// sign that the server is down. So does any member once more than
/// [`meow_common::chain_health::BLAMED_MEMBERS`] have failed the server in
/// a row ([`ChainHealth::blame`]): a server that is down would otherwise
/// fail through each member of the group in turn before the outbound
/// counted it.
pub(crate) fn front_hop_failed() {
    let _ = MEMBER_DIAL.try_with(|dial| dial.front_failed.set(true));
}

/// The member the last group dialled on the current member dial took.
pub(crate) fn last_pick() -> Option<Arc<dyn Proxy>> {
    MEMBER_DIAL
        .try_with(|dial| dial.pick.borrow().clone())
        .ok()
        .flatten()
}

/// Whether the last group dialled on the current member dial took the
/// member named `name`.
pub(crate) fn last_pick_is(name: &str) -> bool {
    MEMBER_DIAL
        .try_with(|dial| {
            dial.pick
                .borrow()
                .as_ref()
                .is_some_and(|p| p.name() == name)
        })
        .unwrap_or(false)
}

/// Run `dial`, a dial or probe of a member, and name the member that the
/// last group dialled on its path took: a chained outbound's front hop.
pub(crate) async fn watch_member_dial<T>(
    dial: impl Future<Output = T>,
) -> (T, Option<Arc<dyn Proxy>>) {
    MEMBER_DIAL
        .scope(MemberDial::default(), async {
            let output = dial.await;
            (output, MEMBER_DIAL.with(|dial| dial.pick.take()))
        })
        .await
}

/// Counts the outcome of one member dial. The dial runs under the outer
/// dial deadline itself, so expiry settles like any failure, front-hop
/// verdicts included: the innermost dial on a path times out first, and a
/// front hop's member takes the blame before the group dialling the chained
/// outbound sees the error. A dial dropped at or past the deadline without
/// being polled to its end still counts on drop, for the member alone.
/// Capturing the deadline avoids consulting task-local state during
/// destruction. Ordinary cancellation before expiry is not a node failure,
/// and completed dials are counted once.
struct DialAttempt<'a> {
    group_name: &'a str,
    tracker: &'a DialFailureTracker,
    member: &'a Arc<dyn Proxy>,
    deadline: Option<tokio::time::Instant>,
}

impl<'a> DialAttempt<'a> {
    fn new(
        group_name: &'a str,
        tracker: &'a DialFailureTracker,
        member: &'a Arc<dyn Proxy>,
    ) -> Self {
        Self {
            group_name,
            tracker,
            member,
            deadline: meow_common::dial::dial_deadline(),
        }
    }

    /// Dial the member with `dial` and count the outcome.
    async fn run<T>(
        mut self,
        dial: impl Future<Output = meow_common::Result<T>>,
    ) -> meow_common::Result<T> {
        // The member dial enclosing this one learns which member was taken.
        let _ = MEMBER_DIAL.try_with(|outer| outer.pick.replace(Some(Arc::clone(self.member))));
        let deadline = self.deadline;
        let member = self.member.name();
        let (result, front_failed) = MEMBER_DIAL
            .scope(MemberDial::default(), async {
                let result = match deadline {
                    Some(_) => meow_common::with_dial_timeout(member, dial).await,
                    None => dial.await,
                };
                (result, MEMBER_DIAL.with(|dial| dial.front_failed.get()))
            })
            .await;
        self.deadline = None;
        match &result {
            Ok(_) => self.tracker.on_success(),
            Err(err) if front_failed => debug!(
                "proxy-group '{}': not counting a failed dial of '{}' against it: its \
                 dialer-proxy front hop failed ({err})",
                self.group_name,
                self.member.name()
            ),
            Err(err) => record_dial_failure(self.group_name, self.tracker, self.member, err),
        }
        result
    }
}

impl Drop for DialAttempt<'_> {
    fn drop(&mut self) {
        if self
            .deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            let err = MeowError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "outbound dial deadline elapsed",
            ));
            record_dial_failure(self.group_name, self.tracker, self.member, &err);
        }
    }
}

/// The chain target when the dial for `metadata` is a `dialer-proxy` front
/// hop through this group. A dial (`dial`) also records the chained
/// outbound as an owner of the target, for the health check's chain probe;
/// a peek does not.
pub(super) fn front_hop_target(
    health: &ChainHealth,
    metadata: &Metadata,
    dial: bool,
) -> Option<ChainTarget> {
    let hop = crate::dialer::front_hop_for(metadata)?;
    if dial {
        if let Some(owner) = &hop.owner {
            health.note_owner(&hop.target, owner);
        }
    }
    Some(hop.target)
}

/// The member a front hop to `target` uses. `carrier`, the member that
/// carries the target's chains, when the group keeps them on it: it stays
/// while `usable` accepts it and it is not blocked. Otherwise `pick`, the
/// group's own, unless it is blocked for `target`; then the first of
/// `members` that `usable` accepts and that is not blocked. `members` comes
/// in the group's preference order. With every usable member blocked the
/// target itself is the likelier fault, so the group's own pick stands
/// rather than a dial with nowhere to go. A dial (`dial`) notes a member
/// other than `pick` on the connection.
#[allow(
    clippy::too_many_arguments,
    reason = "one call per group kind; a struct would only name the same values"
)]
pub(super) fn front_hop_pick(
    group: &str,
    health: &ChainHealth,
    target: &ChainTarget,
    pick: Arc<dyn Proxy>,
    carrier: Option<Arc<dyn Proxy>>,
    members: impl FnOnce() -> Vec<Arc<dyn Proxy>>,
    usable: impl Fn(&Arc<dyn Proxy>) -> bool,
    dial: bool,
) -> Arc<dyn Proxy> {
    if let Some(carrier) = carrier.filter(|c| usable(c) && !health.is_blocked(target, c.name())) {
        if dial && carrier.name() != pick.name() {
            conn_note!(
                Dial,
                "{group}: keeping dialer-proxy chains to {target} on {}",
                carrier.name()
            );
        }
        return carrier;
    }
    if !health.is_blocked(target, pick.name()) {
        return pick;
    }
    let blocked = health.blocked(target);
    let Some(alternative) = members()
        .into_iter()
        .find(|p| usable(p) && !blocked.iter().any(|(name, _)| name == p.name()))
    else {
        return pick;
    };
    if dial {
        conn_note!(
            Dial,
            "{group}: {} cannot reach {target} as a dialer-proxy front, using {}",
            pick.name(),
            alternative.name()
        );
    }
    alternative
}

/// Judge `conn`, a front hop to `target` through `member`, on its first
/// read (see [`meow_common::chain_health`]). A member that is an automatic
/// group itself judges its own pick, so it is not wrapped again.
pub(super) fn watch_front_hop(
    conn: Box<dyn ProxyConn>,
    group: &str,
    health: &Arc<ChainHealth>,
    target: ChainTarget,
    member: &Arc<dyn Proxy>,
) -> Box<dyn ProxyConn> {
    if member.chain_health().is_some() {
        return conn;
    }
    let carrier = health.carrier(&target).as_deref() == Some(member.name());
    Box::new(FrontHopConn {
        conn,
        pending: Some(PendingVerdict {
            group: SmolStr::new(group),
            health: Arc::clone(health),
            target,
            member: Arc::clone(member),
            carrier,
            wrote: false,
            shut: false,
        }),
    })
}

/// Log and record that `member` took over the chains to `target` through
/// `group` from `change.from`. The logbook entry's subject is the chained
/// outbound, so a user following it sees every front-hop move in one place.
pub(crate) fn carrier_changed(
    group: &str,
    target: &ChainTarget,
    member: &str,
    change: &CarrierChange,
) {
    let from = change.from.as_str();
    let why = change
        .reason
        .map_or_else(String::new, |reason| format!(": {reason}"));
    info!(
        "proxy-group '{group}': dialer-proxy chains to {target} moved from '{from}'{why} to \
         '{member}'"
    );
    let subject = change.owner.as_deref().unwrap_or(group);
    let mut event = logbook::event(
        logbook::kind::DIALER_PROXY_SWITCH,
        Level::Info,
        format!("'{subject}' now dials through '{member}' of '{group}' (was '{from}'{why})"),
    )
    .subject(subject)
    .field("group", group)
    .field("from", from)
    .field("to", member);
    if let Some(reason) = change.reason {
        event = event.field("reason", reason);
    }
    event.coalesce().record();
}

/// A front-hop stream that settles one verdict for its member: reached on
/// the first byte read; failed on EOF or an error before that, or on the
/// dial's deadline, once the chained protocol has written. EOF before any
/// write, or after our own shutdown, says nothing about the member. A
/// failure the table puts down to the target ([`ChainHealth::blame`])
/// strikes no member and counts against the chained outbound.
struct FrontHopConn {
    conn: Box<dyn ProxyConn>,
    /// `None` once the verdict is in.
    pending: Option<PendingVerdict>,
}

struct PendingVerdict {
    group: SmolStr,
    health: Arc<ChainHealth>,
    target: ChainTarget,
    member: Arc<dyn Proxy>,
    /// The member carried the target's chains when this one started.
    carrier: bool,
    wrote: bool,
    shut: bool,
}

impl FrontHopConn {
    /// Settle the verdict: reached, or failed for the reason given.
    fn settle(&mut self, failure: Option<&'static str>) {
        let Some(verdict) = self.pending.take() else {
            return;
        };
        let member = verdict.member.name();
        let Some(reason) = failure else {
            if let Some(change) = verdict.health.record_reached(&verdict.target, member) {
                carrier_changed(&verdict.group, &verdict.target, member, &change);
            }
            return;
        };
        if verdict.health.blame(&verdict.target, member) == Blame::Target {
            debug!(
                "proxy-group '{}': dialer-proxy chains to {} fail through member after member \
                 ({reason} through '{member}'); counting it against the chained outbound",
                verdict.group, verdict.target
            );
            return;
        }
        if !verdict.carrier {
            front_hop_failed();
        }
        if let Some(length) =
            verdict
                .health
                .record_failed(&verdict.target, member, ChainVerdict::Passive, reason)
        {
            info!(
                "proxy-group '{}': member '{member}' failed dialer-proxy chains to {} \
                 ({reason}); skipping it for that target for {}s",
                verdict.group,
                verdict.target,
                length.as_secs()
            );
        }
    }

    /// Settle a write: an error before the first byte read is a failure.
    fn on_write(&mut self, poll: &Poll<io::Result<usize>>) {
        let Some(verdict) = self.pending.as_mut() else {
            return;
        };
        match poll {
            Poll::Ready(Ok(n)) if *n > 0 => verdict.wrote = true,
            Poll::Ready(Err(e)) => self.settle(Some(failure_reason(&e.to_string()))),
            _ => {}
        }
    }
}

impl AsyncRead for FrontHopConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let capacity = buf.remaining();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.conn).poll_read(cx, buf);
        if let (Some(verdict), Poll::Ready(result)) = (&this.pending, &poll) {
            let read = buf.filled().len() - before;
            let judged = verdict.wrote && !verdict.shut;
            match result {
                Ok(()) if read > 0 => this.settle(None),
                Ok(()) if capacity == 0 => {}
                Ok(()) if judged => this.settle(Some(CLOSED_BEFORE_REPLY)),
                Err(e) if judged => this.settle(Some(failure_reason(&e.to_string()))),
                Ok(()) | Err(_) => this.pending = None,
            }
        }
        poll
    }
}

impl AsyncWrite for FrontHopConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.conn).poll_write(cx, buf);
        this.on_write(&poll);
        poll
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.conn).poll_write_vectored(cx, bufs);
        this.on_write(&poll);
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.conn.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(verdict) = this.pending.as_mut() {
            verdict.shut = true;
        }
        Pin::new(&mut this.conn).poll_shutdown(cx)
    }
}

impl Drop for FrontHopConn {
    /// A stream that the dial's deadline drops with the chained request
    /// unanswered fails like EOF before a reply: a front member that
    /// black-holes the server's port shows only so while the chained
    /// protocol's handshake waits. Any other drop before a reply, such as a
    /// client giving up, says nothing about the member. The deadline is read
    /// where the stream is dropped: a dial that returned left it behind, so
    /// the end of a relay never counts.
    fn drop(&mut self) {
        let unanswered = self.pending.as_ref().is_some_and(|v| v.wrote && !v.shut);
        if unanswered
            && meow_common::dial::dial_deadline()
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            self.settle(Some(failure_reason("timed out")));
        }
    }
}

impl ProxyConn for FrontHopConn {
    fn remote_destination(&self) -> String {
        self.conn.remote_destination()
    }
}

pub mod dialer_proxy;
pub mod fallback;
pub mod load_balance;
pub mod relay;
pub mod selector;
pub mod selector_store;
pub mod urltest;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_pool_pressure_never_escalates() {
        let tracker = DialFailureTracker::new();
        let error = MeowError::RelayHopFailed {
            hop: 1,
            source: Box::new(MeowError::io_with(
                "adapter",
                meow_common::error::local_resource_limit("bounded pool full"),
            )),
        };
        for _ in 0..100 {
            assert!(!tracker.on_failure(&error));
        }
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            assert!(!tracker.on_failure(&proxy_err("timed out")));
        }
        assert!(tracker.on_failure(&proxy_err("timed out")));
    }

    fn proxy_err(msg: &str) -> MeowError {
        MeowError::Proxy(msg.into())
    }

    #[test]
    fn five_failures_within_window_escalate() {
        let tracker = DialFailureTracker::new();
        for i in 1..DIAL_FAILURE_THRESHOLD {
            assert!(
                !tracker.on_failure(&proxy_err("dial timed out")),
                "failure {i} is below the threshold"
            );
        }
        assert!(
            tracker.on_failure(&proxy_err("dial timed out")),
            "the 5th failure within the window escalates"
        );
        // Escalation resets the streak, so a fresh window starts over.
        assert!(!tracker.on_failure(&proxy_err("dial timed out")));
    }

    #[test]
    fn connection_refused_escalates_immediately() {
        let tracker = DialFailureTracker::new();
        assert!(tracker.on_failure(&proxy_err("connection refused")));
    }

    #[test]
    fn connection_refused_leaves_the_streak_intact() {
        // mihomo's refused fast path does not touch failedTimes.
        let tracker = DialFailureTracker::new();
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            tracker.on_failure(&proxy_err("dial timed out"));
        }
        assert!(tracker.on_failure(&proxy_err("connection refused")));
        assert!(
            tracker.on_failure(&proxy_err("dial timed out")),
            "the pre-refused streak still counts toward the threshold"
        );
    }

    #[test]
    fn success_resets_the_streak() {
        let tracker = DialFailureTracker::new();
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            tracker.on_failure(&proxy_err("dial timed out"));
        }
        tracker.on_success();
        for i in 1..DIAL_FAILURE_THRESHOLD {
            assert!(
                !tracker.on_failure(&proxy_err("dial timed out")),
                "failure {i} after a success does not escalate"
            );
        }
        assert!(tracker.on_failure(&proxy_err("dial timed out")));
    }

    #[test]
    fn not_supported_failures_never_escalate() {
        let tracker = DialFailureTracker::new();
        for _ in 0..100 {
            assert!(!tracker.on_failure(&MeowError::NotSupported("udp".into())));
        }
    }

    #[test]
    fn udp_unsupported_failures_never_escalate() {
        let tracker = DialFailureTracker::new();
        for _ in 0..100 {
            assert!(!tracker.on_failure(&MeowError::UdpNotSupported));
        }
    }

    #[test]
    fn capability_errors_inside_relay_hops_never_escalate() {
        // A refusal from hop N of a chained front is the same permanent
        // property as a top-level NotSupported (issue #663).
        let tracker = DialFailureTracker::new();
        let err = MeowError::RelayHopFailed {
            hop: 2,
            source: Box::new(MeowError::NotSupported("udp".into())),
        };
        for _ in 0..100 {
            assert!(!tracker.on_failure(&err));
        }
        // io-boundary reconstitution reaches the tracker as
        // `MeowError::Io` with `Unsupported` kind.
        let io = MeowError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dialer-proxy udp: refused",
        ));
        for _ in 0..100 {
            assert!(!tracker.on_failure(&io));
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_resource_errors_never_escalate() {
        // EMFILE & friends mean this process is out of fds — dead-marking
        // a healthy member for local pressure blackholes the group
        // (issue #668).
        let tracker = DialFailureTracker::new();
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            let err = MeowError::Io(std::io::Error::from_raw_os_error(errno));
            for _ in 0..100 {
                assert!(
                    !tracker.on_failure(&err),
                    "errno {errno} must not count toward dead-marking"
                );
            }
        }
        // The same errno inside a relay-hop wrapper is equally local.
        let nested = MeowError::RelayHopFailed {
            hop: 1,
            source: Box::new(MeowError::Io(std::io::Error::from_raw_os_error(
                libc::EMFILE,
            ))),
        };
        for _ in 0..100 {
            assert!(!tracker.on_failure(&nested));
        }
        // ...while an unrelated errno still counts toward the threshold.
        let timed_out = MeowError::Io(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            assert!(!tracker.on_failure(&timed_out));
        }
        assert!(tracker.on_failure(&timed_out));
    }

    #[test]
    fn window_expiry_drops_the_streak() {
        let tracker = DialFailureTracker::new();
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            tracker.on_failure(&proxy_err("dial timed out"));
        }
        // Age the window without sleeping in the test.
        tracker.state.lock().first_at =
            Some(Instant::now() - DIAL_FAILURE_WINDOW - Duration::from_millis(50));
        assert!(
            !tracker.on_failure(&proxy_err("dial timed out")),
            "a streak older than the window is dropped"
        );
        // A fresh window needs a full new streak to escalate.
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            assert!(!tracker.on_failure(&proxy_err("dial timed out")));
        }
        assert!(tracker.on_failure(&proxy_err("dial timed out")));
    }
}

#[cfg(test)]
mod dial_timeout_tests;

#[cfg(test)]
mod front_hop_tests;
