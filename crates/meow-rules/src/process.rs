use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct ProcessRule {
    process_name: SmolStr,
    adapter: Adapter,
}

impl ProcessRule {
    pub fn new(name: &str, adapter: &str) -> Self {
        Self {
            process_name: name.into(),
            adapter: intern_adapter(adapter),
        }
    }
}

impl Rule for ProcessRule {
    fn rule_type(&self) -> RuleType {
        RuleType::ProcessName
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        // Process lookup is performed once in the tunnel match engine before
        // rule iteration — see `meow_tunnel::match_engine::match_rules`. By
        // the time we reach this rule `metadata.process` is either populated
        // with the result of that lookup or empty if the lookup failed /
        // wasn't attempted on this platform.
        metadata.process.eq_ignore_ascii_case(&self.process_name)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.process_name
    }

    fn should_find_process(&self) -> bool {
        // `find_process` has real implementations only where
        // `PROCESS_LOOKUP_SUPPORTED`; elsewhere demanding it is pure cost
        // (#625). An inbound that supplies `metadata.process` needs no
        // lookup either way.
        meow_common::process_lookup::PROCESS_LOOKUP_SUPPORTED
    }

    fn never_matches(&self) -> bool {
        // Where neither a native lookup nor the inbound can fill
        // `metadata.process`, it stays empty forever — a non-empty payload
        // is provably dead. (An empty payload matches the empty field;
        // leave that quirk alone.)
        !meow_common::process_lookup::process_info_available() && !self.process_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn process_rule_live_and_demands_lookup_supported() {
        let r = ProcessRule::new("curl", "DIRECT");
        assert!(!r.never_matches());
        assert!(r.should_find_process());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[test]
    fn process_rule_dead_and_demands_nothing_unsupported() {
        let r = ProcessRule::new("curl", "DIRECT");
        assert!(r.never_matches());
        assert!(!r.should_find_process());
        // An empty payload still matches the permanently-empty field —
        // the quirk is preserved rather than pruned.
        let empty = ProcessRule::new("", "DIRECT");
        assert!(!empty.never_matches());
        assert!(empty.match_metadata(&Metadata::default(), &RuleMatchHelper));
    }

    #[test]
    fn process_rule_matches_name_case_insensitive() {
        let r = ProcessRule::new("curl", "DIRECT");
        let meta = Metadata {
            process: "CURL".into(),
            ..Default::default()
        };
        assert!(r.match_metadata(&meta, &RuleMatchHelper));
    }
}
