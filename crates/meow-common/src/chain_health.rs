//! Per-target member verdicts for `dialer-proxy` front hops.
//!
//! An automatic group used as a `dialer-proxy` carries each chained
//! outbound's connection to that outbound's *server*. A member can pass the
//! group's URL test and still fail to reach that server. Airports often run
//! audit rules that drop non-standard ports, so `HK-01` reaches
//! `www.gstatic.com:443` but not `snell.example.com:8443`. The member's
//! single health bit cannot express this. The dial cannot see it either: a
//! lazy front (VLESS, Trojan, Shadowsocks) returns before the remote side
//! connects, so the failure only shows as EOF on the chained protocol's
//! first read.
//!
//! [`ChainHealth`] records which members failed to carry a chain to which
//! target. On a front-hop dial, an automatic group skips the members blocked
//! for that dial's target, and only for that target. Verdicts come from two
//! sources:
//!
//! - **Passive**: the first read on a front-hop stream. Data means the chain
//!   reached the target. EOF or an error before any byte, after the chained
//!   protocol wrote its request, is a failure. [`PASSIVE_STRIKES`] failures
//!   in a row block the member.
//! - **Active**: the health check probes the chain itself, `[member,
//!   outbound]` to the group's test URL. One failed probe blocks the member.
//!   A member blocked already is probed again, so a passing probe can clear
//!   it early; failing again keeps it blocked past the next round, without
//!   lengthening its backoff.
//!
//! Blocks back off exponentially, from [`BASE_BLOCK`] up to [`MAX_BLOCK`].
//! When a block runs out, the member is on probation: the next dial may use
//! it, and one more failure blocks it again for twice as long. Any success
//! clears the member.
//!
//! A table that tracks carriers ([`ChainHealth::tracking_carriers`]) also
//! remembers, per target, the member that last carried a chain there. A
//! url-test group keeps a target's front hops on its carrier while that
//! member is alive and not blocked, rather than moving them each time the
//! fastest member to the test URL changes: the chained outbound sits behind
//! one member that is known to reach its server, and moves only when that
//! member fails. A fallback group keeps its order, so its front hops return
//! to an earlier member once that member is no longer blocked; its carrier
//! still names the member whose failures count against the chained
//! outbound. When the carrier goes down for its group, the next member to
//! reach the target takes over.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use smol_str::SmolStr;

use crate::{metadata_ip_literal, Metadata};

/// Passive failures in a row that block a member. One is not enough: when
/// the chained protocol relays the user's stream (Shadowsocks, VLESS), a
/// destination that closes without answering also reads as EOF before the
/// first byte.
pub const PASSIVE_STRIKES: u8 = 2;

/// Length of a member's first block.
pub const BASE_BLOCK: Duration = Duration::from_secs(5 * 60);

/// Ceiling for repeated blocks. Generous: without the chain probe, each
/// block that runs out costs a user connection to find the member still
/// failing, while a passing probe clears a block whatever its length.
pub const MAX_BLOCK: Duration = Duration::from_secs(6 * 60 * 60);

/// Targets one group remembers. A chain target is a proxy server, so a real
/// config has a handful; the bound only caps a provider that churns server
/// names. The least recently used target is evicted first.
const MAX_TARGETS: usize = 64;

/// Outbounds remembered per target as candidates for the active probe.
const MAX_OWNERS: usize = 4;

/// The server a front hop dials: where the chained outbound connects.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ChainTarget {
    Addr(SocketAddr),
    Host { host: SmolStr, port: u16 },
}

impl ChainTarget {
    /// The target of a front-hop dial. IP literals fold to
    /// [`ChainTarget::Addr`] whether they arrive in `dst_ip` or in `host`.
    pub fn from_metadata(metadata: &Metadata) -> Option<Self> {
        let port = metadata.dst_port;
        if !metadata.host.is_empty() {
            return Some(match metadata_ip_literal(&metadata.host) {
                Some(ip) => Self::Addr(SocketAddr::new(ip, port)),
                None => Self::Host {
                    host: metadata.host.clone(),
                    port,
                },
            });
        }
        metadata
            .dst_ip
            .map(|ip| Self::Addr(SocketAddr::new(ip, port)))
    }

    /// The target of an adapter's `server:port` address, as
    /// [`ProxyAdapter::addr`](crate::ProxyAdapter::addr) gives it. Agrees
    /// with [`Self::from_metadata`] on the dial to that server.
    pub fn from_server_addr(addr: &str) -> Option<Self> {
        let (host, port) = addr.rsplit_once(':')?;
        let port = port.parse().ok()?;
        if host.is_empty() {
            return None;
        }
        Some(match metadata_ip_literal(host) {
            Some(ip) => Self::Addr(SocketAddr::new(ip, port)),
            None => Self::Host {
                host: SmolStr::new(host),
                port,
            },
        })
    }
}

impl fmt::Display for ChainTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(addr) => write!(f, "{addr}"),
            Self::Host { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// Where a verdict comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainVerdict {
    /// The first read on a front-hop stream. A failure counts as one strike.
    Passive,
    /// A chain probe from the health check. A failure blocks the member at
    /// once, and the block lasts at least `hold`, so it outlives the gap
    /// until the next probe round.
    Probe { hold: Duration },
}

/// A target's entry: outbounds seen dialling it, members with a record and
/// the member carrying its chains.
struct TargetState {
    owners: Vec<SmolStr>,
    members: HashMap<SmolStr, MemberState>,
    carrier: Option<SmolStr>,
    used: Instant,
}

impl TargetState {
    fn new(now: Instant) -> Self {
        Self {
            owners: Vec::new(),
            members: HashMap::new(),
            carrier: None,
            used: now,
        }
    }

    fn is_blocked_at(&self, member: &str, now: Instant) -> bool {
        self.members.get(member).is_some_and(|m| m.blocked_at(now))
    }
}

/// The member carrying the chains to a target changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierChange {
    /// The member that carried them before.
    pub from: SmolStr,
    /// Why `from` stopped: its last failure, while it is blocked.
    pub reason: Option<&'static str>,
    /// The outbound last seen dialling the target.
    pub owner: Option<SmolStr>,
}

/// How a member reached a target, for [`ChainHealth::reached_at`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// A front-hop dial, which the group sent through the member.
    Dial,
    /// A chain probe, while the carrier is usable.
    Probe,
    /// A chain probe, while the carrier is not a live member any more.
    OverDownCarrier,
}

/// [`CarrierChange::reason`] for a carrier its group no longer has alive.
const CARRIER_DOWN: &str = "down";

/// Failures since the last success. `level` counts blocks in a row: it sets
/// the next block's length, and a non-zero level puts the member on
/// probation once the block expires. `reason` describes the last failure.
#[derive(Clone, Copy, Default)]
struct MemberState {
    strikes: u8,
    level: u8,
    blocked_until: Option<Instant>,
    reason: &'static str,
}

impl MemberState {
    fn blocked_at(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|until| until > now)
    }

    /// Block for the next level's length, or `hold` if that is longer.
    fn block(&mut self, now: Instant, hold: Duration) -> Duration {
        self.level = self.level.saturating_add(1);
        self.strikes = 0;
        let length = block_length(self.level).max(hold);
        self.blocked_until = Some(now + length);
        length
    }
}

/// `BASE_BLOCK` doubled for each level past the first, capped at
/// `MAX_BLOCK`.
fn block_length(level: u8) -> Duration {
    let doublings = u32::from(level.saturating_sub(1)).min(8);
    BASE_BLOCK.saturating_mul(1 << doublings).min(MAX_BLOCK)
}

/// The verdict table of one automatic group; see the module docs.
#[derive(Default)]
pub struct ChainHealth {
    targets: RwLock<HashMap<ChainTarget, TargetState>>,
    /// Remember each target's carrier.
    carriers: bool,
}

impl ChainHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// A table that also remembers each target's carrier, for a group whose
    /// front hops to one target take one member at a time (url-test,
    /// fallback).
    pub fn tracking_carriers() -> Self {
        Self {
            carriers: true,
            ..Self::default()
        }
    }

    /// The member that last carried a chain to `target`, if this table
    /// tracks carriers.
    pub fn carrier(&self, target: &ChainTarget) -> Option<SmolStr> {
        self.targets.read().get(target)?.carrier.clone()
    }

    /// Remember that `owner` dials `target` through this group. The health
    /// check probes the chain to `target` through one of its owners.
    pub fn note_owner(&self, target: &ChainTarget, owner: &str) {
        if let Some(state) = self.targets.read().get(target) {
            if state.owners.iter().any(|o| o == owner) {
                return;
            }
        }
        let mut targets = self.targets.write();
        let state = entry(&mut targets, target, Instant::now());
        if state.owners.iter().any(|o| o == owner) {
            return;
        }
        if state.owners.len() >= MAX_OWNERS {
            state.owners.remove(0);
        }
        state.owners.push(SmolStr::new(owner));
    }

    /// Every known target with its owners, for the health check.
    pub fn targets(&self) -> Vec<(ChainTarget, Vec<SmolStr>)> {
        self.targets
            .read()
            .iter()
            .map(|(target, state)| (target.clone(), state.owners.clone()))
            .collect()
    }

    /// Whether `member` is blocked for `target` now.
    pub fn is_blocked(&self, target: &ChainTarget, member: &str) -> bool {
        self.is_blocked_at(target, member, Instant::now())
    }

    fn is_blocked_at(&self, target: &ChainTarget, member: &str, now: Instant) -> bool {
        self.targets
            .read()
            .get(target)
            .is_some_and(|state| state.is_blocked_at(member, now))
    }

    /// Members blocked for `target` now, with the time left on each block.
    pub fn blocked(&self, target: &ChainTarget) -> Vec<(SmolStr, Duration)> {
        let now = Instant::now();
        self.targets
            .read()
            .get(target)
            .map_or_else(Vec::new, |state| {
                state
                    .members
                    .iter()
                    .filter_map(|(name, m)| {
                        let until = m.blocked_until.filter(|until| *until > now)?;
                        Some((name.clone(), until - now))
                    })
                    .collect()
            })
    }

    /// A front hop to `target` through `member` worked: forget the member's
    /// record. A table tracking carriers makes `member` the target's
    /// carrier, as the dial chose it; returns the change when it replaced
    /// another member.
    pub fn record_reached(&self, target: &ChainTarget, member: &str) -> Option<CarrierChange> {
        self.reached_at(target, member, Reach::Dial, Instant::now())
    }

    /// A chain probe to `target` through `member` worked: forget the
    /// member's record. It becomes the carrier only when the target has
    /// none, or its carrier is blocked or, as the caller sees it
    /// (`carrier_down`), no longer a live member of the group: a probe round
    /// reaches through several members, and the carrier stays while it
    /// works.
    pub fn record_probe_reached(
        &self,
        target: &ChainTarget,
        member: &str,
        carrier_down: bool,
    ) -> Option<CarrierChange> {
        let reach = if carrier_down {
            Reach::OverDownCarrier
        } else {
            Reach::Probe
        };
        self.reached_at(target, member, reach, Instant::now())
    }

    fn reached_at(
        &self,
        target: &ChainTarget,
        member: &str,
        reach: Reach,
        now: Instant,
    ) -> Option<CarrierChange> {
        {
            let targets = self.targets.read();
            let state = targets.get(target);
            let known = state.is_some_and(|state| state.members.contains_key(member));
            let settled = !self.carriers
                || state.is_some_and(|state| match &state.carrier {
                    Some(carrier) if carrier == member => true,
                    Some(carrier) => reach == Reach::Probe && !state.is_blocked_at(carrier, now),
                    None => false,
                });
            if !known && settled {
                return None;
            }
        }
        let mut targets = self.targets.write();
        let state = if self.carriers {
            entry(&mut targets, target, now)
        } else {
            targets.get_mut(target)?
        };
        state.members.remove(member);
        if !self.carriers || state.carrier.as_deref() == Some(member) {
            return None;
        }
        let adopt = reach != Reach::Probe
            || state
                .carrier
                .as_ref()
                .is_none_or(|carrier| state.is_blocked_at(carrier, now));
        if !adopt {
            return None;
        }
        let from = state.carrier.replace(SmolStr::new(member))?;
        let reason = state
            .members
            .get(&from)
            .filter(|m| m.blocked_at(now))
            .map(|m| m.reason)
            .or((reach == Reach::OverDownCarrier).then_some(CARRIER_DOWN));
        Some(CarrierChange {
            from,
            reason,
            owner: state.owners.last().cloned(),
        })
    }

    /// The chain to `target` through `member` failed, for `reason`, one of
    /// [`failure_reason`]'s. Returns the block length when this failure
    /// blocked the member; a member blocked already stays so, and gets
    /// `None`.
    pub fn record_failed(
        &self,
        target: &ChainTarget,
        member: &str,
        verdict: ChainVerdict,
        reason: &'static str,
    ) -> Option<Duration> {
        self.failed_at(target, member, verdict, reason, Instant::now())
    }

    #[cfg(test)]
    fn record_failed_at(
        &self,
        target: &ChainTarget,
        member: &str,
        verdict: ChainVerdict,
        now: Instant,
    ) -> Option<Duration> {
        self.failed_at(target, member, verdict, "test", now)
    }

    fn failed_at(
        &self,
        target: &ChainTarget,
        member: &str,
        verdict: ChainVerdict,
        reason: &'static str,
        now: Instant,
    ) -> Option<Duration> {
        let mut targets = self.targets.write();
        let state = entry(&mut targets, target, now);
        let m = state.members.entry(SmolStr::new(member)).or_default();
        m.reason = reason;
        match verdict {
            // A probe round tries a blocked member again, so a passing probe
            // can clear it early. Failing again, it stays blocked past the
            // next round, at the same level: one block, not one per round.
            ChainVerdict::Probe { hold } if m.blocked_at(now) => {
                m.blocked_until = m.blocked_until.max(Some(now + hold));
                None
            }
            ChainVerdict::Probe { hold } => Some(m.block(now, hold)),
            ChainVerdict::Passive => {
                // A dial that slipped through while the member was blocked:
                // every member blocked, or a dial already past the check.
                if m.blocked_at(now) {
                    return None;
                }
                m.strikes = m.strikes.saturating_add(1);
                (m.level > 0 || m.strikes >= PASSIVE_STRIKES).then(|| m.block(now, Duration::ZERO))
            }
        }
    }
}

/// A dial or probe failure in a few words, for records that outlive the
/// process: error text can carry server addresses, which the logbook never
/// keeps (ADR-0014), and a fixed vocabulary lets repeats fold into one
/// entry.
pub fn failure_reason(error: &str) -> &'static str {
    let error = error.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| error.contains(w));
    if has(&["timed out", "timeout", "deadline"]) {
        "timed out"
    } else if has(&["refused"]) {
        "connection refused"
    } else if has(&["reset", "aborted"]) {
        "connection reset"
    } else if has(&["unexpected status"]) {
        "unexpected HTTP status"
    } else if has(&["tls", "ssl", "certificate", "handshake"]) {
        "TLS handshake failed"
    } else if has(&["eof", "closed", "broken pipe"]) {
        CLOSED_BEFORE_REPLY
    } else if has(&["resolve", "dns", "lookup", "no address"]) {
        "name resolution failed"
    } else if has(&["unreachable"]) {
        "network unreachable"
    } else {
        "connection failed"
    }
}

/// The [`failure_reason`] of a chain whose stream ended before the first
/// byte of a reply.
pub const CLOSED_BEFORE_REPLY: &str = "closed before any reply";

/// `target`'s entry, created on first use. A new entry past
/// [`MAX_TARGETS`] evicts the least recently used one.
fn entry<'a>(
    targets: &'a mut HashMap<ChainTarget, TargetState>,
    target: &ChainTarget,
    now: Instant,
) -> &'a mut TargetState {
    if !targets.contains_key(target) && targets.len() >= MAX_TARGETS {
        if let Some(oldest) = targets
            .iter()
            .min_by_key(|(_, state)| state.used)
            .map(|(t, _)| t.clone())
        {
            targets.remove(&oldest);
        }
    }
    let state = targets
        .entry(target.clone())
        .or_insert_with(|| TargetState::new(now));
    state.used = now;
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ChainTarget {
        ChainTarget::Host {
            host: "snell.example.com".into(),
            port: 8443,
        }
    }

    const PROBE: ChainVerdict = ChainVerdict::Probe {
        hold: Duration::ZERO,
    };

    #[test]
    fn target_folds_ip_literals_from_host_and_dst_ip() {
        let from_host = Metadata {
            host: "[2001:db8::1]".into(),
            dst_port: 8443,
            ..Default::default()
        };
        let from_ip = Metadata {
            dst_ip: Some("2001:db8::1".parse().unwrap()),
            dst_port: 8443,
            ..Default::default()
        };
        assert_eq!(
            ChainTarget::from_metadata(&from_host),
            ChainTarget::from_metadata(&from_ip)
        );
        assert_eq!(
            ChainTarget::from_metadata(&from_ip).unwrap().to_string(),
            "[2001:db8::1]:8443"
        );
        assert_eq!(ChainTarget::from_metadata(&Metadata::default()), None);
    }

    #[test]
    fn server_addr_agrees_with_the_dial_metadata() {
        let dial = |host: &str, ip: Option<&str>| {
            ChainTarget::from_metadata(&Metadata {
                host: host.into(),
                dst_ip: ip.map(|ip| ip.parse().unwrap()),
                dst_port: 8443,
                ..Default::default()
            })
        };
        assert_eq!(
            ChainTarget::from_server_addr("snell.example.com:8443"),
            dial("snell.example.com", None)
        );
        assert_eq!(
            ChainTarget::from_server_addr("203.0.113.7:8443"),
            dial("", Some("203.0.113.7"))
        );
        // `format!("{server}:{port}")` with a bare or a bracketed v6 server.
        assert_eq!(
            ChainTarget::from_server_addr("2001:db8::1:8443"),
            dial("", Some("2001:db8::1"))
        );
        assert_eq!(
            ChainTarget::from_server_addr("[2001:db8::1]:8443"),
            dial("", Some("2001:db8::1"))
        );
        assert_eq!(ChainTarget::from_server_addr(""), None);
        assert_eq!(ChainTarget::from_server_addr(":8443"), None);
        assert_eq!(ChainTarget::from_server_addr("host"), None);
    }

    #[test]
    fn two_passive_failures_in_a_row_block() {
        let health = ChainHealth::new();
        let now = Instant::now();
        let t = target();
        assert_eq!(
            health.record_failed_at(&t, "HK-01", ChainVerdict::Passive, now),
            None
        );
        assert!(!health.is_blocked_at(&t, "HK-01", now));
        assert_eq!(
            health.record_failed_at(&t, "HK-01", ChainVerdict::Passive, now),
            Some(BASE_BLOCK)
        );
        assert!(health.is_blocked_at(&t, "HK-01", now));
        assert!(!health.is_blocked_at(&t, "HK-02", now), "only that member");
        let other = ChainTarget::Host {
            host: "snell.example.com".into(),
            port: 443,
        };
        assert!(
            !health.is_blocked_at(&other, "HK-01", now),
            "only that target"
        );
    }

    #[test]
    fn a_success_between_failures_resets_the_strikes() {
        let health = ChainHealth::new();
        let t = target();
        health.record_failed(&t, "HK-01", ChainVerdict::Passive, "eof");
        health.record_reached(&t, "HK-01");
        assert_eq!(
            health.record_failed(&t, "HK-01", ChainVerdict::Passive, "eof"),
            None
        );
        assert!(!health.is_blocked(&t, "HK-01"));
    }

    #[test]
    fn a_failed_probe_blocks_at_once_for_at_least_the_hold() {
        let health = ChainHealth::new();
        let now = Instant::now();
        let t = target();
        let hold = Duration::from_secs(20 * 60);
        assert_eq!(
            health.record_failed_at(&t, "HK-01", ChainVerdict::Probe { hold }, now),
            Some(hold)
        );
        assert!(health.is_blocked_at(&t, "HK-01", now + BASE_BLOCK));
        assert!(!health.is_blocked_at(&t, "HK-01", now + hold));
    }

    #[test]
    fn an_expired_block_leaves_the_member_on_probation_with_backoff() {
        let health = ChainHealth::new();
        let t = target();
        let start = Instant::now();
        health.record_failed_at(&t, "HK-01", PROBE, start);
        let expired = start + BASE_BLOCK;
        assert!(!health.is_blocked_at(&t, "HK-01", expired), "block ran out");
        // On probation one passive failure is enough, and the block doubles.
        assert_eq!(
            health.record_failed_at(&t, "HK-01", ChainVerdict::Passive, expired),
            Some(BASE_BLOCK * 2)
        );
        let mut now = expired;
        for _ in 0..8 {
            now += MAX_BLOCK;
            health.record_failed_at(&t, "HK-01", PROBE, now);
        }
        assert!(health.is_blocked_at(&t, "HK-01", now + MAX_BLOCK - Duration::from_secs(1)));
        assert!(
            !health.is_blocked_at(&t, "HK-01", now + MAX_BLOCK),
            "capped"
        );
    }

    #[test]
    fn success_clears_the_block_and_the_probation() {
        let health = ChainHealth::new();
        let t = target();
        health.record_failed(&t, "HK-01", PROBE, "eof");
        assert!(health.is_blocked(&t, "HK-01"));
        health.record_reached(&t, "HK-01");
        assert!(!health.is_blocked(&t, "HK-01"));
        assert_eq!(
            health.record_failed(&t, "HK-01", ChainVerdict::Passive, "eof"),
            None,
            "back to a clean slate: one passive failure is a strike"
        );
    }

    #[test]
    fn a_passive_failure_while_blocked_does_not_extend_the_block() {
        let health = ChainHealth::new();
        let now = Instant::now();
        let t = target();
        health.record_failed_at(&t, "HK-01", PROBE, now);
        assert_eq!(
            health.record_failed_at(&t, "HK-01", ChainVerdict::Passive, now),
            None
        );
        assert!(!health.is_blocked_at(&t, "HK-01", now + BASE_BLOCK));
    }

    #[test]
    fn a_table_without_carriers_remembers_none() {
        let health = ChainHealth::new();
        let t = target();
        assert_eq!(health.record_reached(&t, "HK-01"), None);
        assert_eq!(health.record_probe_reached(&t, "HK-01", false), None);
        assert_eq!(health.carrier(&t), None);
    }

    #[test]
    fn a_dial_makes_its_member_the_carrier() {
        let health = ChainHealth::tracking_carriers();
        let t = target();
        health.note_owner(&t, "daniel");
        assert_eq!(
            health.record_reached(&t, "HK-01"),
            None,
            "the first carrier"
        );
        assert_eq!(health.carrier(&t).as_deref(), Some("HK-01"));
        assert_eq!(health.record_reached(&t, "HK-01"), None, "unchanged");
        assert_eq!(
            health.record_reached(&t, "HK-02"),
            Some(CarrierChange {
                from: "HK-01".into(),
                reason: None,
                owner: Some("daniel".into()),
            })
        );
        assert_eq!(health.carrier(&t).as_deref(), Some("HK-02"));
    }

    #[test]
    fn a_probe_takes_over_only_from_a_blocked_carrier() {
        let health = ChainHealth::tracking_carriers();
        let now = Instant::now();
        let t = target();
        assert_eq!(health.reached_at(&t, "HK-01", Reach::Probe, now), None);
        assert_eq!(
            health.carrier(&t).as_deref(),
            Some("HK-01"),
            "no carrier yet"
        );
        assert_eq!(health.reached_at(&t, "HK-02", Reach::Probe, now), None);
        assert_eq!(
            health.carrier(&t).as_deref(),
            Some("HK-01"),
            "a working carrier stays"
        );

        health.failed_at(&t, "HK-01", PROBE, "timed out", now);
        let change = health.reached_at(&t, "HK-02", Reach::Probe, now).unwrap();
        assert_eq!(
            (change.from.as_str(), change.reason),
            ("HK-01", Some("timed out"))
        );
        assert_eq!(health.carrier(&t).as_deref(), Some("HK-02"));
    }

    #[test]
    fn a_probe_takes_over_from_a_carrier_that_is_down() {
        let health = ChainHealth::tracking_carriers();
        let t = target();
        health.record_reached(&t, "HK-01");
        let change = health.record_probe_reached(&t, "HK-02", true).unwrap();
        assert_eq!(
            (change.from.as_str(), change.reason),
            ("HK-01", Some(CARRIER_DOWN))
        );
        assert_eq!(
            health.record_probe_reached(&t, "HK-03", false),
            None,
            "the new carrier works"
        );
        assert_eq!(health.carrier(&t).as_deref(), Some("HK-02"));
    }

    #[test]
    fn a_failed_probe_while_blocked_holds_the_block_at_its_level() {
        let health = ChainHealth::new();
        let start = Instant::now();
        let t = target();
        // Rounds a minute apart, holding a block for two, as the health
        // check does.
        let round = Duration::from_secs(60);
        let hold = round * 2;
        let probe = ChainVerdict::Probe { hold };
        assert_eq!(
            health.record_failed_at(&t, "HK-01", probe, start),
            Some(BASE_BLOCK)
        );
        // Still blocked at each round: no new block, and the backoff level
        // stays where it was.
        let mut now = start;
        for _ in 0..10 {
            now += round;
            assert_eq!(health.record_failed_at(&t, "HK-01", probe, now), None);
        }
        assert!(
            health.is_blocked_at(&t, "HK-01", now + hold - Duration::from_secs(1)),
            "each failure holds it past the next round"
        );
        let now = now + hold;
        assert!(!health.is_blocked_at(&t, "HK-01", now));
        assert_eq!(
            health.record_failed_at(&t, "HK-01", probe, now),
            Some(BASE_BLOCK * 2),
            "one level up, once the block ran out"
        );
    }

    #[test]
    fn a_carrier_change_names_the_reason_only_while_blocked() {
        let health = ChainHealth::tracking_carriers();
        let now = Instant::now();
        let t = target();
        health.reached_at(&t, "HK-01", Reach::Dial, now);
        health.failed_at(&t, "HK-01", ChainVerdict::Passive, "closed", now);
        let change = health.reached_at(&t, "HK-02", Reach::Dial, now).unwrap();
        assert_eq!(change.reason, None, "one strike does not block");
    }

    #[test]
    fn failure_reasons_keep_no_addresses() {
        for (error, reason) in [
            (
                "dial: connect 203.0.113.7:8443: Connection refused (os error 111)",
                "connection refused",
            ),
            (
                "read: Connection reset by peer (os error 104)",
                "connection reset",
            ),
            ("eof before status line", CLOSED_BEFORE_REPLY),
            ("snell: unexpected eof reading reply", CLOSED_BEFORE_REPLY),
            ("tls: handshake failure", "TLS handshake failed"),
            ("unexpected status 403", "unexpected HTTP status"),
            ("outbound dial deadline elapsed", "timed out"),
            (
                "failed to lookup address information",
                "name resolution failed",
            ),
            (
                "something else at snell.example.com:8443",
                "connection failed",
            ),
        ] {
            assert_eq!(failure_reason(error), reason, "{error}");
        }
    }

    #[test]
    fn owners_are_deduplicated_and_bounded() {
        let health = ChainHealth::new();
        let t = target();
        health.note_owner(&t, "daniel");
        health.note_owner(&t, "daniel");
        assert_eq!(
            health.targets(),
            vec![(t.clone(), vec![SmolStr::new("daniel")])]
        );
        for i in 0..MAX_OWNERS {
            health.note_owner(&t, &format!("o{i}"));
        }
        let owners = &health.targets()[0].1;
        assert_eq!(owners.len(), MAX_OWNERS);
        assert!(
            !owners.iter().any(|o| o == "daniel"),
            "oldest owner evicted"
        );
    }

    #[test]
    fn targets_are_bounded_least_recently_used_first() {
        let health = ChainHealth::new();
        let start = Instant::now();
        for i in 0..MAX_TARGETS {
            let t = ChainTarget::Host {
                host: format!("s{i}.example.com").into(),
                port: 8443,
            };
            let at = start + Duration::from_secs(i as u64);
            health.record_failed_at(&t, "HK-01", ChainVerdict::Passive, at);
        }
        let newest = ChainTarget::Host {
            host: "new.example.com".into(),
            port: 8443,
        };
        health.record_failed_at(
            &newest,
            "HK-01",
            ChainVerdict::Passive,
            start + Duration::from_secs(1000),
        );
        let targets: Vec<String> = health
            .targets()
            .into_iter()
            .map(|(t, _)| t.to_string())
            .collect();
        assert_eq!(targets.len(), MAX_TARGETS);
        assert!(!targets.contains(&"s0.example.com:8443".to_string()));
        assert!(targets.contains(&"new.example.com:8443".to_string()));
    }
}
