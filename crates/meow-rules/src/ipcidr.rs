use ipnet::IpNet;
use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct IpCidrRule {
    cidr: IpNet,
    cidr_str: SmolStr,
    adapter: Adapter,
    is_src: bool,
    no_resolve: bool,
}

impl IpCidrRule {
    pub fn new(
        cidr: &str,
        adapter: &str,
        is_src: bool,
        no_resolve: bool,
    ) -> Result<Self, ipnet::AddrParseError> {
        let parsed: IpNet = cidr.parse()?;
        Ok(Self {
            cidr: parsed,
            cidr_str: cidr.into(),
            adapter: intern_adapter(adapter),
            is_src,
            no_resolve,
        })
    }
}

impl Rule for IpCidrRule {
    fn rule_type(&self) -> RuleType {
        if self.is_src {
            RuleType::SrcIpCidr
        } else {
            RuleType::IpCidr
        }
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let ip = if self.is_src {
            metadata.src_ip
        } else {
            metadata.dst_ip
        };
        ip.is_some_and(|addr| self.cidr.contains(&addr))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.cidr_str
    }

    fn should_resolve_ip(&self) -> bool {
        !self.is_src && !self.no_resolve
    }
}
