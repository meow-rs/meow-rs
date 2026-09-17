//! IN-TYPE rule — matches on the inbound connection type (`Metadata.conn_type`).
//!
//! upstream: `rules/common/inbound.go`
//!
//! Mapping:
//!   HTTP   → ConnType::Http OR ConnType::Https
//!   HTTPS  → ConnType::Https only
//!   SOCKS5 → ConnType::Socks5
//!   TPROXY → ConnType::TProxy
//!   INNER  → ConnType::Inner
//!
//! Unknown value → hard parse error (Class A per ADR-0002).

use meow_common::{ConnType, Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct InTypeRule {
    raw: SmolStr,
    adapter: Adapter,
    /// Bitmask stored as a small fixed array; we have at most 2 variants to match.
    match_http: bool,
    match_https: bool,
    match_socks5: bool,
    match_tproxy: bool,
    match_inner: bool,
}

impl InTypeRule {
    /// Parse the IN-TYPE value string into a rule.
    ///
    /// upstream: `rules/common/inbound.go::NewInType`
    pub fn new(type_str: &str, adapter: &str) -> Result<Self, String> {
        let mut r = Self {
            raw: type_str.into(),
            adapter: intern_adapter(adapter),
            match_http: false,
            match_https: false,
            match_socks5: false,
            match_tproxy: false,
            match_inner: false,
        };
        match type_str.to_uppercase().as_str() {
            "HTTP" => {
                r.match_http = true;
                r.match_https = true;
            }
            "HTTPS" => r.match_https = true,
            "SOCKS5" => r.match_socks5 = true,
            "TPROXY" => r.match_tproxy = true,
            "INNER" => r.match_inner = true,
            other => {
                return Err(format!(
                "unknown IN-TYPE value '{other}'; expected HTTP, HTTPS, SOCKS5, TPROXY, or INNER \
                     (Class A per ADR-0002, upstream: rules/common/inbound.go)"
            ))
            }
        }
        Ok(r)
    }
}

impl Rule for InTypeRule {
    fn rule_type(&self) -> RuleType {
        RuleType::InType
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        match metadata.conn_type {
            ConnType::Http => self.match_http,
            ConnType::Https => self.match_https,
            ConnType::Socks5 => self.match_socks5,
            ConnType::TProxy => self.match_tproxy,
            ConnType::Inner => self.match_inner,
            _ => false,
        }
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ConnType, Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_with_conn(conn_type: ConnType) -> Metadata {
        Metadata {
            conn_type,
            ..Default::default()
        }
    }

    #[test]
    fn in_type_http_matches_http_and_https() {
        let r = InTypeRule::new("HTTP", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
        assert!(r.match_metadata(&meta_with_conn(ConnType::Https), &helper()));
    }

    #[test]
    fn in_type_https_matches_only_https() {
        let r = InTypeRule::new("HTTPS", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::Https), &helper()));
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
    }

    #[test]
    fn in_type_socks5_matches_socks5() {
        let r = InTypeRule::new("SOCKS5", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::Socks5), &helper()));
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
    }

    #[test]
    fn in_type_tproxy_matches_tproxy() {
        let r = InTypeRule::new("TPROXY", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::TProxy), &helper()));
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
    }

    #[test]
    fn in_type_unknown_value_hard_errors() {
        // Class A per ADR-0002: upstream: rules/common/inbound.go
        // NOT upstream: unknown IN-TYPE is silently skipped in some versions
        assert!(InTypeRule::new("QUIC", "DIRECT").is_err());
    }
}
