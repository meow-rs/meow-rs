use crate::metadata::Metadata;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    GeoSite,
    GeoIp,
    SrcGeoIp,
    IpCidr,
    SrcIpCidr,
    SrcPort,
    DstPort,
    InPort,
    Dscp,
    ProcessName,
    ProcessPath,
    Network,
    Uid,
    Match,
    RuleSet,
    And,
    Or,
    Not,
    DomainWildcard,
    IpSuffix,
    SrcIpSuffix,
    IpAsn,
    SrcIpAsn,
    SubRule,
    InName,
    InType,
    InUser,
}

impl RuleType {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleType::Domain => "DOMAIN",
            RuleType::DomainSuffix => "DOMAIN-SUFFIX",
            RuleType::DomainKeyword => "DOMAIN-KEYWORD",
            RuleType::DomainRegex => "DOMAIN-REGEX",
            RuleType::GeoSite => "GEOSITE",
            RuleType::GeoIp => "GEOIP",
            RuleType::SrcGeoIp => "SRC-GEOIP",
            RuleType::IpCidr => "IP-CIDR",
            RuleType::SrcIpCidr => "SRC-IP-CIDR",
            RuleType::SrcPort => "SRC-PORT",
            RuleType::DstPort => "DST-PORT",
            RuleType::InPort => "IN-PORT",
            RuleType::Dscp => "DSCP",
            RuleType::ProcessName => "PROCESS-NAME",
            RuleType::ProcessPath => "PROCESS-PATH",
            RuleType::Network => "NETWORK",
            RuleType::Uid => "UID",
            RuleType::Match => "MATCH",
            RuleType::RuleSet => "RULE-SET",
            RuleType::And => "AND",
            RuleType::Or => "OR",
            RuleType::Not => "NOT",
            RuleType::DomainWildcard => "DOMAIN-WILDCARD",
            RuleType::IpSuffix => "IP-SUFFIX",
            RuleType::SrcIpSuffix => "SRC-IP-SUFFIX",
            RuleType::IpAsn => "IP-ASN",
            RuleType::SrcIpAsn => "SRC-IP-ASN",
            RuleType::SubRule => "SUB-RULE",
            RuleType::InName => "IN-NAME",
            RuleType::InType => "IN-TYPE",
            RuleType::InUser => "IN-USER",
        }
    }
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleType::Domain => write!(f, "DOMAIN"),
            RuleType::DomainSuffix => write!(f, "DOMAIN-SUFFIX"),
            RuleType::DomainKeyword => write!(f, "DOMAIN-KEYWORD"),
            RuleType::DomainRegex => write!(f, "DOMAIN-REGEX"),
            RuleType::GeoSite => write!(f, "GEOSITE"),
            RuleType::GeoIp => write!(f, "GEOIP"),
            RuleType::SrcGeoIp => write!(f, "SRC-GEOIP"),
            RuleType::IpCidr => write!(f, "IP-CIDR"),
            RuleType::SrcIpCidr => write!(f, "SRC-IP-CIDR"),
            RuleType::SrcPort => write!(f, "SRC-PORT"),
            RuleType::DstPort => write!(f, "DST-PORT"),
            RuleType::InPort => write!(f, "IN-PORT"),
            RuleType::Dscp => write!(f, "DSCP"),
            RuleType::ProcessName => write!(f, "PROCESS-NAME"),
            RuleType::ProcessPath => write!(f, "PROCESS-PATH"),
            RuleType::Network => write!(f, "NETWORK"),
            RuleType::Uid => write!(f, "UID"),
            RuleType::Match => write!(f, "MATCH"),
            RuleType::RuleSet => write!(f, "RULE-SET"),
            RuleType::And => write!(f, "AND"),
            RuleType::Or => write!(f, "OR"),
            RuleType::Not => write!(f, "NOT"),
            RuleType::DomainWildcard => write!(f, "DOMAIN-WILDCARD"),
            RuleType::IpSuffix => write!(f, "IP-SUFFIX"),
            RuleType::SrcIpSuffix => write!(f, "SRC-IP-SUFFIX"),
            RuleType::IpAsn => write!(f, "IP-ASN"),
            RuleType::SrcIpAsn => write!(f, "SRC-IP-ASN"),
            RuleType::SubRule => write!(f, "SUB-RULE"),
            RuleType::InName => write!(f, "IN-NAME"),
            RuleType::InType => write!(f, "IN-TYPE"),
            RuleType::InUser => write!(f, "IN-USER"),
        }
    }
}

/// Helper passed to `Rule::match_metadata`. Historically this carried a
/// platform-specific `find_process` closure, but process lookup is now
/// performed once per dispatch in the tunnel match engine (which populates
/// `Metadata.process` / `process_path` / `uid` before rule iteration). The
/// struct is kept as an empty marker so the `Rule` trait signature can grow
/// future per-match context (e.g. shared regex cache) without touching every
/// call site again.
#[derive(Default)]
pub struct RuleMatchHelper;

/// Match-time verdict for a matched rule's target adapter (issue #533).
/// Mirrors the checks upstream's `match()` loop applies between
/// `rule.Match` and returning the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetCheck {
    /// The adapter resolves and may carry this connection.
    Usable,
    /// Absent from the registry, or present but incapable for this
    /// connection class (e.g. no UDP support on a UDP flow) — the rule is
    /// skipped with a warning, mihomo's `continue`.
    Missing,
    /// The adapter unwraps to the `PASS` built-in — the rule is skipped
    /// silently (upstream `continue GetRules` on `C.Pass`).
    Pass,
}

/// Registry probe consulted by the match engines for every matched rule.
/// A plain `Fn(&str) -> bool` closure covers `check` (true → [`Usable`],
/// false → [`Missing`]) and leaves the pass probes at their defaults, so
/// existing call sites and tests keep compiling unchanged.
///
/// upstream: `tunnel/tunnel.go::match` — `proxies[ada]` lookup, the
/// `Unwrap` walk for `C.Pass`/`C.Rematch`, and the UDP `SupportUDP`
/// continue; `CheckPassRule` on `RuleMatchHelper` for sub-rule scans.
///
/// [`Usable`]: TargetCheck::Usable
/// [`Missing`]: TargetCheck::Missing
pub trait TargetProbe {
    fn check(&self, name: &str) -> TargetCheck;
    /// Whether `name` unwraps to a `PASS-RULE`-typed adapter — consulted by
    /// SUB-RULE inner scans (upstream `matchSubRules`' `CheckPassRule`).
    fn is_pass_rule(&self, _name: &str) -> bool {
        false
    }
}

/// Convenience adapter for tests and the legacy call sites: a plain
/// existence predicate. **It can never report [`TargetCheck::Pass`] and
/// `is_pass_rule` always answers `false`** — a production engine that
/// needs pass semantics must implement `TargetProbe` for real (see
/// `RouteTargetProbe` in meow-tunnel).
impl<F: Fn(&str) -> bool> TargetProbe for F {
    fn check(&self, name: &str) -> TargetCheck {
        if self(name) {
            TargetCheck::Usable
        } else {
            TargetCheck::Missing
        }
    }
}

pub trait Rule: Send + Sync {
    fn rule_type(&self) -> RuleType;
    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool;
    fn adapter(&self) -> &str;
    fn payload(&self) -> &str;
    fn should_resolve_ip(&self) -> bool {
        false
    }
    fn should_find_process(&self) -> bool {
        false
    }

    /// True iff this rule can be proven at build time to never match any
    /// metadata (e.g. a GEOSITE rule whose database was never loaded). The
    /// answer must be constant for the lifetime of the rule object: the rule
    /// IR compiler prunes such rules from its scan plan entirely, so a rule
    /// whose matchability can change at runtime must return `false`.
    fn never_matches(&self) -> bool {
        false
    }

    /// Concrete-type escape hatch for the rule IR compiler: rule types that
    /// can be lowered to native opcodes (their match state is cheap to share
    /// — `Arc` handles or `Copy` matchers) override this to return `self`.
    /// The default `None` keeps the rule on the virtual-dispatch fallback
    /// path. Lowering is an optimization only; `match_metadata` remains the
    /// source of truth for semantics.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }

    /// Match against metadata and, on match, return the routing target.
    ///
    /// Default: `Some(self.adapter())` when `match_metadata`
    /// returns true, else `None`. Override only when the resolved target
    /// must come from some other source — notably `SUB-RULE`, whose
    /// target is the matched inner rule's adapter rather than any field
    /// stored on the outer rule.
    ///
    /// Returns a borrowed `&str` so rule matching itself never allocates on
    /// the heap, even when adapter names are longer than SmolStr's inline
    /// capacity. Callers that need to retain the value past the route-table
    /// snapshot can materialize it outside the rule engine.
    ///
    /// upstream: `rules/logic/logic.go::matchSubRules` — returns
    /// `(bool, adapter)` from the inner rule, not from the SUB-RULE
    /// wrapper.
    ///
    /// `probe` carries the registry checks inner scans need (today only
    /// [`TargetProbe::is_pass_rule`]); most rules ignore it. A rule whose
    /// resolved target differs from `adapter()` must also be declared
    /// `TargetPlan::DynamicAdapter` in the compiled engine (today only
    /// [`RuleType::SubRule`] qualifies).
    fn match_and_resolve<'a>(
        &'a self,
        metadata: &Metadata,
        helper: &RuleMatchHelper,
        probe: &dyn TargetProbe,
    ) -> Option<&'a str> {
        let _ = probe;
        if self.match_metadata(metadata, helper) {
            Some(self.adapter())
        } else {
            None
        }
    }
}
