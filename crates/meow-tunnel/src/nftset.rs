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
use std::sync::Mutex;
use std::time::{Duration, Instant};

use meow_common::nftset::NftsetConfig;
use meow_common::{Metadata, Network, Rule, RuleMatchHelper, RuleType};
use meow_rules::logic::{AndRule, NotRule, OrRule};
use meow_rules::rule_set_rule::RuleSetRule;

use crate::tunnel::Tunnel;

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

/// Whether a connection to `domain` at `ip` may be routed anywhere but
/// DIRECT by `rules`.
pub fn needs_core(rules: &[Box<dyn Rule>], domain: &str, ip: IpAddr) -> bool {
    let md = Metadata {
        network: Network::Tcp,
        host: domain.into(),
        dst_ip: Some(ip),
        ..Metadata::default()
    };
    let h = RuleMatchHelper;
    for rule in rules {
        let direct = rule.adapter().eq_ignore_ascii_case("DIRECT");
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
    /// their timeout. Cleared when it grows past `SEEN_CAP`.
    seen: HashMap<IpAddr, Instant>,
    /// Per family (v4, v6): the set rejected an element timeout (no `flags
    /// timeout`).
    #[cfg(target_os = "linux")]
    no_timeout: [bool; 2],
    #[cfg(target_os = "linux")]
    warned: bool,
}

#[cfg(target_os = "linux")]
const SEEN_CAP: usize = 8192;

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
                warned: false,
            }),
        }
    }
}

impl meow_dns::answer_hook::AnswerHook for NftsetHook {
    fn on_answer(&self, domain: &str, ip: IpAddr, ttl: Duration) {
        let Some(set) = self.cfg.set_for(ip) else {
            return;
        };
        let route = self.tunnel.route_snapshot();
        if !needs_core(&route.rules, domain, ip) {
            return;
        }
        let timeout = self.cfg.timeout.max(ttl);
        let now = Instant::now();
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.seen.get(&ip).is_some_and(|exp| *exp > now + timeout / 2) {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            let st = &mut *st;
            if st.writer.is_none() {
                match meow_common::nftset::NftWriter::new() {
                    Ok(w) => st.writer = Some(w),
                    Err(e) => {
                        if !st.warned {
                            st.warned = true;
                            tracing::warn!("dns.nftset: netlink socket: {e}");
                        }
                        return;
                    }
                }
            }
            let fam = usize::from(ip.is_ipv6());
            let Some(w) = st.writer.as_mut() else { return };
            let mut res = w.add(set, ip, (!st.no_timeout[fam]).then_some(timeout));
            if matches!(&res, Err(e) if e.raw_os_error() == Some(libc::EINVAL))
                && !st.no_timeout[fam]
            {
                // A set without `flags timeout` refuses element timeouts.
                res = w.add(set, ip, None);
                if res.is_ok() {
                    st.no_timeout[fam] = true;
                    tracing::warn!(
                        "dns.nftset: {}#{} has no `flags timeout`; elements never expire",
                        set.table,
                        set.set
                    );
                }
            }
            match res {
                Ok(()) => {
                    if st.seen.len() >= SEEN_CAP {
                        st.seen.clear();
                    }
                    st.seen.insert(ip, now + timeout);
                }
                Err(e) => {
                    if !st.warned {
                        st.warned = true;
                        tracing::warn!("dns.nftset: add to {}#{}: {e}", set.table, set.set);
                    }
                    // A dead socket (ENOBUFS, EBADF...) is reopened next time.
                    st.writer = None;
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
    meow_dns::answer_hook::install(cfg.map(|cfg| {
        std::sync::Arc::new(NftsetHook::new(tunnel.clone(), cfg))
            as std::sync::Arc<dyn meow_dns::answer_hook::AnswerHook>
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_rules::parser::parse_rule;

    fn rules(lines: &[&str]) -> Vec<Box<dyn Rule>> {
        lines
            .iter()
            .map(|l| parse_rule(l, &Default::default()).unwrap())
            .collect()
    }

    #[test]
    fn blacklist_config_marks_only_proxied_destinations() {
        let r = rules(&[
            "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
            "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,udp.example)),ProxyUDP",
            "DOMAIN-SUFFIX,openai.com,AI",
            "IP-CIDR,203.0.113.0/24,Proxy",
            "DOMAIN-SUFFIX,ru,DIRECT",
            "MATCH,DIRECT",
        ]);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(needs_core(&r, "chatgpt.openai.com", ip));
        assert!(
            needs_core(&r, "a.udp.example", ip),
            "scoped Maybe, non-DIRECT"
        );
        assert!(needs_core(&r, "x.ru", "203.0.113.9".parse().unwrap()));
        assert!(!needs_core(&r, "yandex.ru", ip));
        assert!(
            !needs_core(&r, "example.org", ip),
            "the unscoped UDP/443 rule is skipped"
        );
    }

    #[test]
    fn whitelist_and_logic() {
        let r = rules(&["NOT,((DOMAIN-SUFFIX,local)),Proxy", "MATCH,DIRECT"]);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(needs_core(&r, "example.org", ip));
        assert!(!needs_core(&r, "nas.local", ip));
        let r = rules(&["OR,((DST-PORT,22),(DOMAIN,a.test)),Proxy", "MATCH,Proxy"]);
        assert!(needs_core(&r, "b.test", ip), "falls to MATCH,Proxy");
    }
}
