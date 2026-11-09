//! `dns.nftset` verdict: would the rules send a connection to
//! `domain` at `ip` through the core? Answers that would get their address
//! added to an nftables set (see `meow_common::nftset`), so a firewall that
//! intercepts only that set leaves DIRECT destinations to kernel forwarding.
//!
//! A DNS answer carries no port, network, source or process, so each rule is
//! judged three-valued over the destination facts alone:
//!
//! - **Yes / No** — the rule is decided by domain and IP (DOMAIN*, GEOSITE,
//!   GEOIP, IP-CIDR, IP-SUFFIX, IP-ASN, non-source RULE-SET, MATCH, and
//!   logic over those);
//! - **Maybe, scoped** — it could match, and a destination fact it depends
//!   on holds (`AND,((NETWORK,UDP),(RULE-SET,x))` with `x` matching): a
//!   non-DIRECT target means the destination needs the core;
//! - **Maybe, unscoped** — it depends on nothing destination-specific
//!   (`AND,((NETWORK,UDP),(DST-PORT,443))`): no per-address set can express
//!   it, so it is skipped — the firewall applies such rules by port itself.
//!
//! The scan stops at the first Yes; the address is added unless that target
//! is DIRECT. Group targets count as the core (a selector may pick DIRECT
//! later — safe in this direction). Classical rule-sets are matched as a
//! whole on the destination; their port/network entries are not seen.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meow_common::nftset::NftsetConfig;
use meow_common::{
    AdapterType, Metadata, Network, Proxy, Rule, RuleMatchHelper, RuleType, TunnelMode,
};
use meow_rules::logic::{AndRule, NotRule, OrRule};
use meow_rules::rule_set_rule::RuleSetRule;

use crate::tunnel::{RouteTable, Tunnel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    Yes,
    No,
    Maybe { scoped: bool },
}

fn judge(rule: &dyn Rule, md: &Metadata, h: &RuleMatchHelper) -> Tri {
    use RuleType as T;
    if rule.never_matches() {
        return Tri::No;
    }
    let by_match = |r: &dyn Rule| {
        if r.match_metadata(md, h) {
            Tri::Yes
        } else {
            Tri::No
        }
    };
    match rule.rule_type() {
        T::Domain
        | T::DomainSuffix
        | T::DomainKeyword
        | T::DomainRegex
        | T::DomainWildcard
        | T::GeoSite
        | T::GeoIp
        | T::IpCidr
        | T::IpSuffix
        | T::IpAsn => by_match(rule),
        T::Match => Tri::Yes,
        T::RuleSet => match rule.as_any().and_then(|a| a.downcast_ref::<RuleSetRule>()) {
            Some(rs) if !rs.is_src() => by_match(rule),
            _ => Tri::Maybe { scoped: false },
        },
        T::And => {
            let Some(r) = rule.as_any().and_then(|a| a.downcast_ref::<AndRule>()) else {
                return Tri::Maybe { scoped: true };
            };
            let mut all_yes = true;
            let mut scoped = false;
            for c in r.sub_rules() {
                match judge(c.as_ref(), md, h) {
                    Tri::No => return Tri::No,
                    Tri::Yes => scoped = true,
                    Tri::Maybe { scoped: s } => {
                        all_yes = false;
                        scoped |= s;
                    }
                }
            }
            if all_yes {
                Tri::Yes
            } else {
                Tri::Maybe { scoped }
            }
        }
        T::Or => {
            let Some(r) = rule.as_any().and_then(|a| a.downcast_ref::<OrRule>()) else {
                return Tri::Maybe { scoped: true };
            };
            let mut all_no = true;
            let mut scoped = false;
            for c in r.sub_rules() {
                match judge(c.as_ref(), md, h) {
                    Tri::Yes => return Tri::Yes,
                    Tri::No => {}
                    Tri::Maybe { scoped: s } => {
                        all_no = false;
                        scoped |= s;
                    }
                }
            }
            if all_no {
                Tri::No
            } else {
                Tri::Maybe { scoped }
            }
        }
        T::Not => {
            let Some(r) = rule.as_any().and_then(|a| a.downcast_ref::<NotRule>()) else {
                return Tri::Maybe { scoped: true };
            };
            match judge(r.inner(), md, h) {
                Tri::Yes => Tri::No,
                Tri::No => Tri::Yes,
                m @ Tri::Maybe { .. } => m,
            }
        }
        // SUB-RULE branches to rules of its own: assume it can.
        T::SubRule => Tri::Maybe { scoped: true },
        _ => Tri::Maybe { scoped: false },
    }
}

/// The `RouteTargetProbe::unwraps_to` walk on this verdict's synthetic
/// metadata: `true` when any hop of `start`'s group chain carries `want`.
/// A target that unwraps to PASS is skipped by the match loop, so the
/// verdict skips it the same way.
fn unwraps_to(start: &Arc<dyn Proxy>, md: &Metadata, want: AdapterType) -> bool {
    const MAX_UNWRAP_HOPS: usize = 16;
    let mut cur = Arc::clone(start);
    for _ in 0..MAX_UNWRAP_HOPS {
        if cur.adapter_type() == want {
            return true;
        }
        let Some(next) = cur.unwrap_proxy(md, false) else {
            return false;
        };
        cur = next;
    }
    false
}

/// Whether a connection to `domain` at `ip` may be routed anywhere but
/// DIRECT under `mode` — mirrors `resolve_proxy_inner`'s mode
/// short-circuits, the compiled scan's disabled-rule mask, and
/// `materialize_rule_match`/`RouteTargetProbe` target semantics on
/// `route`.
pub fn needs_core(route: &RouteTable, mode: TunnelMode, domain: &str, ip: IpAddr) -> bool {
    match mode {
        // `resolve_proxy_inner` never reaches the rules in these modes.
        TunnelMode::Direct => return false,
        TunnelMode::Global => {
            // GLOBAL wins the whole flow; without such an entry the mode
            // falls back to the built-in direct adapter.
            return route.proxies.get("GLOBAL").is_some_and(|p| {
                !matches!(
                    p.adapter_type(),
                    AdapterType::Direct | AdapterType::Compatible
                )
            });
        }
        TunnelMode::Rule => {}
    }
    let md = Metadata {
        network: Network::Tcp,
        host: domain.into(),
        dst_ip: Some(ip),
        ..Metadata::default()
    };
    let h = RuleMatchHelper;
    for (i, rule) in route.rules.iter().enumerate() {
        // The compiled plan masks disabled rules out (`build_masked`);
        // the verdict must too — a disabled DIRECT rule deciding first
        // would under-add.
        if route.rule_stats.is_disabled(i) {
            continue;
        }
        let target = rule.adapter();
        let direct = if rule.rule_type() == RuleType::SubRule {
            // A SUB-RULE's `adapter()` is the block name, not a proxy —
            // the inner rules' target is unknowable at verdict time, so
            // assume core: `judge` already answers `Maybe{scoped}`.
            false
        } else if target == "DIRECT" {
            // The built-in resolves without a registry entry.
            true
        } else {
            // `RouteTargetProbe::check`: a target absent from the
            // registry reports Missing and the match loop continues —
            // so does this scan. A real proxy named e.g. `direct` is
            // judged by its type, like `materialize_rule_match`.
            let Some(p) = route.proxies.get(target) else {
                continue;
            };
            if unwraps_to(p, &md, AdapterType::Pass) {
                continue;
            }
            matches!(
                p.adapter_type(),
                AdapterType::Direct | AdapterType::Compatible
            )
        };
        match judge(rule.as_ref(), &md, &h) {
            Tri::Yes => return !direct,
            Tri::Maybe { scoped: true } if !direct => return true,
            _ => {}
        }
    }
    false
}

/// The `dns.nftset` answer hook: verdict over the tunnel's live rules, then
/// one acked netlink add per new or half-expired element.
pub struct NftsetHook {
    tunnel: Tunnel,
    cfg: NftsetConfig,
    state: Mutex<HookState>,
}

struct HookState {
    #[cfg(target_os = "linux")]
    writer: Option<meow_common::nftset::NftWriter>,
    /// Elements added and when they expire, to skip re-adds within half
    /// their timeout. Expired entries are shed at `SEEN_CAP` before the
    /// map is cleared outright.
    seen: HashMap<IpAddr, Instant>,
    /// Per family (v4, v6): the set rejected an element timeout (no
    /// `flags timeout`, or a value outside its range).
    #[cfg(target_os = "linux")]
    no_timeout: [bool; 2],
    /// Per family: a permanent failure (missing table/set, missing
    /// CAP_NET_ADMIN) — retrying can never succeed, so the family is
    /// done. Latching it is also that family's one warn.
    #[cfg(target_os = "linux")]
    dead: [bool; 2],
    /// Per family: a transient failure was already warned about.
    #[cfg(target_os = "linux")]
    warned: [bool; 2],
    /// When the last transient failure happened — the next attempt
    /// waits out `TRANSIENT_BACKOFF` so a broken kernel path can't
    /// syscall-storm per query.
    #[cfg(target_os = "linux")]
    last_failure: Option<Instant>,
}

#[cfg(target_os = "linux")]
const SEEN_CAP: usize = 8192;

/// Minimum gap before retrying after a transient failure.
#[cfg(target_os = "linux")]
const TRANSIENT_BACKOFF: Duration = Duration::from_secs(5);

/// Errors retrying can never fix: the named table/set does not exist
/// (ENOENT/ENODEV) or the process lacks CAP_NET_ADMIN (EPERM/EACCES).
/// Everything else — timeout, ENOBUFS, a dead socket — is transient.
#[cfg(target_os = "linux")]
fn permanent(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOENT | libc::ENODEV | libc::EPERM | libc::EACCES)
    )
}

impl NftsetHook {
    pub fn new(tunnel: Tunnel, cfg: NftsetConfig) -> Self {
        Self {
            tunnel,
            cfg,
            state: Mutex::new(HookState {
                #[cfg(target_os = "linux")]
                writer: None,
                seen: HashMap::new(),
                #[cfg(target_os = "linux")]
                no_timeout: [false; 2],
                #[cfg(target_os = "linux")]
                dead: [false; 2],
                #[cfg(target_os = "linux")]
                warned: [false; 2],
                #[cfg(target_os = "linux")]
                last_failure: None,
            }),
        }
    }
}

impl meow_dns::answer_hook::AnswerHook for NftsetHook {
    fn on_answer(&self, domain: &str, ip: IpAddr, ttl: Duration) {
        let Some(set) = self.cfg.set_for(ip) else {
            return;
        };
        let timeout = self.cfg.timeout.max(ttl);
        let now = Instant::now();
        // Fresh enough that no re-add is due — the same test the add
        // path uses below. Checked first so a repeat query never pays
        // the verdict's rules scan (a classical RULE-SET is a linear
        // provider walk).
        let fresh = |st: &HookState| st.seen.get(&ip).is_some_and(|exp| *exp > now + timeout / 2);
        {
            let st = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if fresh(&st) {
                return;
            }
            // A latched-dead or backing-off family never reaches the
            // add — skip the rules verdict too.
            #[cfg(target_os = "linux")]
            if st.dead[usize::from(ip.is_ipv6())]
                || st
                    .last_failure
                    .is_some_and(|t| now.duration_since(t) < TRANSIENT_BACKOFF)
            {
                return;
            }
        }
        let route = self.tunnel.route_snapshot();
        if !needs_core(&route, self.tunnel.mode(), domain, ip) {
            return;
        }
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Re-check under the lock the add runs behind: another worker
        // may have added the element while the verdict scanned.
        if fresh(&st) {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            let st = &mut *st;
            let fam = usize::from(ip.is_ipv6());
            if st.dead[fam]
                || st
                    .last_failure
                    .is_some_and(|t| now.duration_since(t) < TRANSIENT_BACKOFF)
            {
                return;
            }
            if st.writer.is_none() {
                match meow_common::nftset::NftWriter::new() {
                    Ok(w) => st.writer = Some(w),
                    Err(e) => {
                        // AF_NETLINK SOCK_RAW itself needs CAP_NET_ADMIN —
                        // a permanent failure, same as an add-time EPERM.
                        if permanent(&e) {
                            st.dead[fam] = true;
                            tracing::warn!(
                                "dns.nftset: netlink socket: {e} — giving up on \
                                 this address family"
                            );
                        } else {
                            if !st.warned[fam] {
                                st.warned[fam] = true;
                                tracing::warn!("dns.nftset: netlink socket: {e}");
                            }
                            st.last_failure = Some(now);
                        }
                        return;
                    }
                }
            }
            let Some(w) = st.writer.as_mut() else { return };
            let mut res = w.add(set, ip, (!st.no_timeout[fam]).then_some(timeout));
            if matches!(&res, Err(e) if e.raw_os_error() == Some(libc::EINVAL))
                && !st.no_timeout[fam]
            {
                // EINVAL may mean the set lacks `flags timeout` — or
                // that the timeout fell outside the set's
                // timeout_min/max range. Retry without one; latch per
                // family.
                res = w.add(set, ip, None);
                if res.is_ok() {
                    st.no_timeout[fam] = true;
                    tracing::warn!(
                        "dns.nftset: {}#{} rejected the element timeout (EINVAL — \
                         no `flags timeout`, or a value outside the set's range); \
                         elements will be added without one and never expire",
                        set.table,
                        set.set
                    );
                }
            }
            match res {
                Ok(()) => {
                    if st.seen.len() >= SEEN_CAP {
                        // Shed only expired entries first — clearing
                        // live ones re-adds all of them in a burst.
                        st.seen.retain(|_, exp| *exp > now);
                        if st.seen.len() >= SEEN_CAP {
                            st.seen.clear();
                        }
                    }
                    st.seen.insert(ip, now + timeout);
                }
                Err(e) => {
                    if permanent(&e) {
                        st.dead[fam] = true;
                        tracing::warn!(
                            "dns.nftset: add to {}#{}: {e} — set or privilege \
                             missing; giving up on this address family",
                            set.table,
                            set.set
                        );
                    } else {
                        if !st.warned[fam] {
                            st.warned[fam] = true;
                            tracing::warn!("dns.nftset: add to {}#{}: {e}", set.table, set.set);
                        }
                        // A dead socket (ENOBUFS, EBADF...) is reopened
                        // once the backoff lapses.
                        st.writer = None;
                        st.last_failure = Some(now);
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (set, &mut st, timeout);
        }
    }
}

/// Install, replace or (with `None`) remove the process-wide hook — at
/// startup and on every config reload.
pub fn install(tunnel: &Tunnel, cfg: Option<NftsetConfig>) {
    #[cfg(not(target_os = "linux"))]
    {
        // The netlink writer is Linux-only; the config key stays
        // portable (a shared config must not become a parse error), so
        // warn once and leave the hook uninstalled — `pending` stays
        // the cheap `None` path.
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        let configured = cfg.is_some();
        drop(cfg);
        if configured && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!("dns.nftset is Linux-only; ignoring");
        }
        let _ = tunnel;
    }
    #[cfg(target_os = "linux")]
    meow_dns::answer_hook::install(cfg.map(|cfg| {
        Arc::new(NftsetHook::new(tunnel.clone(), cfg)) as Arc<dyn meow_dns::answer_hook::AnswerHook>
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::match_engine::DomainIndex;
    use crate::rule_ir::CompiledRuleSet;
    use meow_rules::parser::parse_rule;
    use smol_str::SmolStr;

    /// A reject-typed stand-in for a proxied target.
    fn stub_proxy() -> Arc<dyn Proxy> {
        Arc::new(meow_config::proxy_parser::WrappedProxy::new(Box::new(
            meow_proxy::RejectAdapter::new(false),
        )))
    }

    fn route_with(lines: &[&str], proxies: HashMap<SmolStr, Arc<dyn Proxy>>) -> RouteTable {
        route_from_rules(
            lines
                .iter()
                .map(|l| parse_rule(l, &Default::default()).unwrap())
                .collect(),
            proxies,
        )
    }

    fn route_from_rules(
        rules: Vec<Box<dyn Rule>>,
        proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
    ) -> RouteTable {
        let rule_stats = crate::rule_stats::RuleStats::new(rules.len());
        RouteTable {
            rules: Arc::new(rules),
            domain_index: Arc::new(DomainIndex::empty()),
            compiled_rules: Arc::new(CompiledRuleSet::empty()),
            proxies: Arc::new(proxies),
            dialer_registry: meow_proxy::dialer::ProxyRegistry::default(),
            rule_stats: Arc::new(rule_stats),
        }
    }

    /// A route table where each of `targets` resolves to a proxied stub.
    fn route(lines: &[&str], targets: &[&str]) -> RouteTable {
        route_with(
            lines,
            targets
                .iter()
                .map(|n| (SmolStr::from(*n), stub_proxy()))
                .collect(),
        )
    }

    #[test]
    fn blacklist_config_marks_only_proxied_destinations() {
        let t = route(
            &[
                "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
                "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,udp.example)),ProxyUDP",
                "DOMAIN-SUFFIX,openai.com,AI",
                "IP-CIDR,203.0.113.0/24,Proxy",
                "DOMAIN-SUFFIX,ru,DIRECT",
                "MATCH,DIRECT",
            ],
            &["REJECT", "ProxyUDP", "AI", "Proxy"],
        );
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(needs_core(&t, TunnelMode::Rule, "chatgpt.openai.com", ip));
        assert!(
            needs_core(&t, TunnelMode::Rule, "a.udp.example", ip),
            "scoped Maybe, non-DIRECT"
        );
        assert!(needs_core(
            &t,
            TunnelMode::Rule,
            "x.ru",
            "203.0.113.9".parse().unwrap()
        ));
        assert!(!needs_core(&t, TunnelMode::Rule, "yandex.ru", ip));
        assert!(
            !needs_core(&t, TunnelMode::Rule, "example.org", ip),
            "the unscoped UDP/443 rule is skipped"
        );
    }

    #[test]
    fn whitelist_and_logic() {
        let t = route(
            &["NOT,((DOMAIN-SUFFIX,local)),Proxy", "MATCH,DIRECT"],
            &["Proxy"],
        );
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(needs_core(&t, TunnelMode::Rule, "example.org", ip));
        assert!(!needs_core(&t, TunnelMode::Rule, "nas.local", ip));
        let t = route(
            &["OR,((DST-PORT,22),(DOMAIN,a.test)),Proxy", "MATCH,Proxy"],
            &["Proxy"],
        );
        assert!(
            needs_core(&t, TunnelMode::Rule, "b.test", ip),
            "falls to MATCH,Proxy"
        );
    }

    #[test]
    fn verdict_respects_mode_and_disabled_rules() {
        let t = route(
            &["DOMAIN-SUFFIX,openai.com,Proxy", "MATCH,DIRECT"],
            &["Proxy"],
        );
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        // resolve_proxy_inner's short-circuits: Direct never reaches the
        // rules; Global answers from the GLOBAL entry alone — absent
        // here, so it falls back to the built-in direct adapter.
        assert!(!needs_core(
            &t,
            TunnelMode::Direct,
            "chatgpt.openai.com",
            ip
        ));
        assert!(!needs_core(
            &t,
            TunnelMode::Global,
            "chatgpt.openai.com",
            ip
        ));
        // A disabled proxied rule must not decide: the masked scan falls
        // through to MATCH,DIRECT like the compiled plan does.
        t.rule_stats.set_disabled(0, true);
        assert!(!needs_core(&t, TunnelMode::Rule, "chatgpt.openai.com", ip));
    }

    #[test]
    fn global_mode_needs_core_when_global_exists() {
        let t = route(&[], &["GLOBAL"]);
        assert!(needs_core(
            &t,
            TunnelMode::Global,
            "anything.example",
            "198.51.100.1".parse().unwrap()
        ));
    }

    #[test]
    fn targets_are_judged_through_the_registry() {
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        // A rule target absent from the registry can't fire — the match
        // loop's Missing check skips it — so the verdict does too.
        let t = route(&["DOMAIN-SUFFIX,example.com,direct"], &[]);
        assert!(!needs_core(&t, TunnelMode::Rule, "a.example.com", ip));
        // A real proxy literally named `direct` is proxied, not the
        // built-in: the adapter type decides, not the name's casing.
        let t = route(&["DOMAIN-SUFFIX,example.com,direct"], &["direct"]);
        assert!(needs_core(&t, TunnelMode::Rule, "a.example.com", ip));
        // A `type: direct` adapter under a non-builtin name is direct,
        // like materialize_rule_match's AdapterType bucketing.
        let t = route_with(
            &["MATCH,Plain"],
            HashMap::from([(
                SmolStr::from("Plain"),
                Arc::new(meow_config::proxy_parser::WrappedProxy::new(Box::new(
                    meow_proxy::DirectAdapter::new(),
                ))) as Arc<dyn Proxy>,
            )]),
        );
        assert!(!needs_core(&t, TunnelMode::Rule, "a.example.com", ip));
    }

    #[test]
    fn sub_rule_targets_are_judged_conservatively() {
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let sub = meow_rules::sub_rule::SubRuleRule::new(
            "sub",
            Arc::new(
                vec![parse_rule("MATCH,DIRECT", &Default::default()).unwrap()]
                    as Vec<Box<dyn Rule>>,
            ),
        );
        let match_direct = parse_rule("MATCH,DIRECT", &Default::default()).unwrap();
        // A SUB-RULE's `adapter()` is the block name — not a proxy —
        // so the registry lookup must not skip it: the inner rules may
        // proxy, and the verdict assumes core either way.
        let t = route_from_rules(vec![Box::new(sub), match_direct], HashMap::new());
        assert!(needs_core(&t, TunnelMode::Rule, "a.example.com", ip));
    }
}
