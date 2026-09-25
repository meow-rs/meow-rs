use std::sync::Arc;

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

use crate::parser::RuleFlags;
use crate::rule_set::{RuleSet, RuleSetBehavior};

/// A `RULE-SET,<name>,<adapter>[,no-resolve][,src]` rule — a thin wrapper
/// that delegates matching to an `Arc<dyn RuleSet>` loaded by the
/// rule-provider subsystem. `is_src` (upstream `isSrc`) makes the set's
/// dst-axis matchers evaluate the source tuple via a swapped metadata
/// clone; upstream intends it for `ipcidr`-behavior providers.
pub struct RuleSetRule {
    name: SmolStr,
    set: Arc<dyn RuleSet>,
    adapter: Adapter,
    flags: RuleFlags,
}

impl RuleSetRule {
    pub fn new(name: &str, set: Arc<dyn RuleSet>, adapter: &str, flags: RuleFlags) -> Self {
        Self {
            name: name.into(),
            set,
            adapter: intern_adapter(adapter),
            flags,
        }
    }

    pub fn rule_set(&self) -> &Arc<dyn RuleSet> {
        &self.set
    }

    /// Whether this entry matches the set on the source axis
    /// (`RULE-SET,...,src`). The IR lowering declines `is_src` entries so
    /// evaluation stays on this wrapper's swapped-metadata path.
    pub fn is_src(&self) -> bool {
        self.flags.is_src
    }
}

impl Rule for RuleSetRule {
    fn rule_type(&self) -> RuleType {
        RuleType::RuleSet
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        // Upstream swaps src/dst in place (`Metadata.SwapSrcDst`); our Rule
        // API takes `&Metadata`, so evaluate on a swapped clone. A
        // domain-behavior set reads only the host — untouched by the swap —
        // so skip the clone there entirely.
        if !self.flags.is_src || self.set.behavior() == RuleSetBehavior::Domain {
            return self.set.matches(metadata, helper);
        }
        let mut swapped = metadata.clone();
        swapped.swap_src_dst();
        self.set.matches(&swapped, helper)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.name
    }

    fn should_resolve_ip(&self) -> bool {
        // `src` implies `no-resolve` upstream (ParseParams): a source-axis
        // match never reads `dst_ip`, so it must not demand a resolution.
        self.set.should_resolve_ip() && !self.flags.no_resolve && !self.flags.is_src
    }

    fn should_find_process(&self) -> bool {
        self.set.should_find_process()
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}
