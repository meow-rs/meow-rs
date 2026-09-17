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
        true
    }
}
