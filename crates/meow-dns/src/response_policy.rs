//! Ordered, synchronous decisions for DNS wire responses.
//! Hostname resolution for outbound sockets deliberately bypasses these rules.

use crate::resolver::NameserverPolicyMatcher;
use std::net::IpAddr;

/// A matching rule terminates the rule scan, including `Forward`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseAction {
    NoData,
    Refused,
    Address { address: IpAddr, ttl: u32 },
    FakeIp,
    Forward,
}

/// A domain-only predicate compiled against one resolver generation.
pub struct ResponseRule {
    pub matcher: NameserverPolicyMatcher,
    /// Empty means all query types; otherwise match the numeric wire type.
    pub query_types: Vec<u16>,
    pub action: ResponseAction,
}

impl ResponseRule {
    pub(crate) fn matches(&self, domain: &str, query_type: u16) -> bool {
        (self.query_types.is_empty() || self.query_types.contains(&query_type))
            && (self.matcher)(domain)
    }
}
