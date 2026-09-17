//! Rule matching engine and parser for the meow-rs proxy kernel.
//!
//! Domain, IP-CIDR, GeoIP, process, and logic (`AND`/`OR`/`NOT`) rules, plus
//! the parser that turns Clash-style rule lines into matchers.

pub mod adapter;
pub mod asn_index;
pub mod country_index;
pub mod domain;
pub mod domain_keyword;
pub mod domain_regex;
pub mod domain_suffix;
pub mod domain_wildcard;
pub mod dscp;
pub mod final_rule;
pub mod geoip;
pub mod geosite;
pub mod geosite_dat;
pub mod geosite_rule;
pub mod in_name;
pub mod in_port;
pub mod in_type;
pub mod in_user;
pub mod ip_asn;
pub mod ip_set;
pub mod ip_suffix;
pub mod ipcidr;
pub mod logic;
pub mod mrs_parser;
pub mod network;
pub mod parser;
pub mod port;
pub mod process;
pub mod process_path;
pub mod rule_set;
pub mod rule_set_rule;
pub mod src_geoip;
pub mod sub_rule;
pub mod uid;

pub use parser::{parse_rule, ParserContext};
pub use rule_set::{
    build_rule_set, build_rule_set_from_mrs, build_rule_set_from_mrs_with_behavior, is_mrs_bytes,
    ClassicalRuleSet, DomainRuleSet, IpCidrRuleSet, RuleSet, RuleSetBehavior, RuleSetFormat,
};
pub use rule_set_rule::RuleSetRule;
