//! The routing policy a named `listeners:` entry declares — carried onto
//! each flow's [`Metadata`] before routing, exactly where upstream's
//! `BaseOption.Additions` (`WithSpecialProxy`/`WithSpecialRules`) stamp
//! it.
//!
//! The override holds *names*, never adapters: the tunnel resolves them
//! per flow against the live route table, so a group reference keeps
//! resolving the group's current members across config reloads (a
//! startup-cached `Arc<dyn Proxy>` would freeze them).

use crate::metadata::Metadata;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

/// `listeners[].proxy` + `listeners[].rule` — a named inbound's
/// forced-route override, immutable after config build.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundRouteOverride {
    /// Forced proxy/group name — lands on `metadata.special_proxy` and
    /// resolves before all mode dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<SmolStr>,
    /// `sub-rules:` block name — lands on `metadata.special_rules` and
    /// replaces the top-level rule list for this flow's scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<SmolStr>,
}

impl InboundRouteOverride {
    /// Normalize raw `proxy`/`rule` values — empty strings mean unset,
    /// and an entry carrying neither yields `None` (no override).
    pub fn new(proxy: Option<&str>, rule: Option<&str>) -> Option<Self> {
        let o = Self {
            proxy: proxy.filter(|s| !s.is_empty()).map(SmolStr::from),
            rule: rule.filter(|s| !s.is_empty()).map(SmolStr::from),
        };
        (o.proxy.is_some() || o.rule.is_some()).then_some(o)
    }

    /// Stamp the override onto `metadata` — run at the same sites
    /// upstream's `Additions` execute: inbound flow construction, before
    /// routing, eager destination resolution, or any rule scan.
    pub fn apply(&self, metadata: &mut Metadata) {
        if let Some(p) = &self.proxy {
            metadata.special_proxy = p.clone();
        }
        if let Some(r) = &self.rule {
            metadata.special_rules = r.clone();
        }
    }
}
