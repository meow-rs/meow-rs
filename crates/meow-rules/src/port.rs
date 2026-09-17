use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct PortRule {
    /// Inclusive `(lo, hi)` pairs; a single port is `(p, p)`.
    ranges: Box<[(u16, u16)]>,
    raw: SmolStr,
    adapter: Adapter,
    is_src: bool,
}

impl PortRule {
    pub fn new(ports: &str, adapter: &str, is_src: bool) -> Result<Self, String> {
        let mut ranges = Vec::new();
        for part in ports.split([',', '/']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((start, end)) = part.split_once('-') {
                let start: u16 = start
                    .trim()
                    .parse()
                    .map_err(|e| format!("invalid port: {e}"))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .map_err(|e| format!("invalid port: {e}"))?;
                if start > end {
                    return Err(format!(
                        "invalid port range {start}-{end}: start must be <= end"
                    ));
                }
                ranges.push((start, end));
            } else {
                let port: u16 = part.parse().map_err(|e| format!("invalid port: {e}"))?;
                ranges.push((port, port));
            }
        }
        if ranges.is_empty() {
            return Err("invalid port: empty range list".to_string());
        }
        Ok(Self {
            ranges: ranges.into_boxed_slice(),
            raw: ports.into(),
            adapter: intern_adapter(adapter),
            is_src,
        })
    }

    fn matches_port(&self, port: u16) -> bool {
        self.ranges
            .iter()
            .any(|&(lo, hi)| (lo..=hi).contains(&port))
    }
}

impl Rule for PortRule {
    fn rule_type(&self) -> RuleType {
        if self.is_src {
            RuleType::SrcPort
        } else {
            RuleType::DstPort
        }
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let port = if self.is_src {
            metadata.src_port
        } else {
            metadata.dst_port
        };
        self.matches_port(port)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }
}
