use crate::dns_parser::{check_domain_key, expand_policy_keys};
use crate::raw::{RawDnsResponseAction, RawDnsResponseRule};
use crate::rule_provider::RuleProvider;
use anyhow::{bail, Context, Result};
use hickory_proto::rr::RecordType;
use meow_dns::resolver::NameserverPolicyMatcher;
use meow_dns::response_policy::{ResponseAction, ResponseRule};
use meow_rules::{geosite::GeositeDB, RuleSet, RuleSetBehavior};
use meow_trie::DomainTrie;
use std::{collections::HashMap, str::FromStr, sync::Arc};

pub(crate) fn build(
    raw: &[RawDnsResponseRule],
    geosite: Option<&Arc<GeositeDB>>,
    providers: &HashMap<String, Arc<RuleProvider>>,
) -> Result<Vec<ResponseRule>> {
    raw.iter()
        .enumerate()
        .map(|(index, rule)| {
            build_rule(rule, geosite, providers)
                .with_context(|| format!("dns.response-rules[{index}]"))
        })
        .collect()
}

fn build_rule(
    raw: &RawDnsResponseRule,
    geosite: Option<&Arc<GeositeDB>>,
    providers: &HashMap<String, Arc<RuleProvider>>,
) -> Result<ResponseRule> {
    let query_types = match &raw.types {
        None => Vec::new(),
        Some(types) if types.is_empty() => bail!("types must contain at least one query type"),
        Some(types) => types
            .iter()
            .map(|name| {
                let name = name.trim().to_ascii_uppercase();
                if let Some(number) = name.strip_prefix("TYPE") {
                    return number
                        .parse::<u16>()
                        .context("invalid numeric DNS query type");
                }
                RecordType::from_str(&name)
                    .map(u16::from)
                    .context("invalid DNS query type")
            })
            .collect::<Result<Vec<_>>>()?,
    };
    if raw.action != RawDnsResponseAction::Address && (raw.address.is_some() || raw.ttl.is_some()) {
        bail!("address and ttl are only valid for the address action");
    }
    let action = match raw.action {
        RawDnsResponseAction::NoData => ResponseAction::NoData,
        RawDnsResponseAction::Refused => ResponseAction::Refused,
        RawDnsResponseAction::Forward => ResponseAction::Forward,
        RawDnsResponseAction::FakeIp => {
            // Only A/AAAA queries ever get a fake IP — a `types` list
            // with no address family makes the rule a silent no-op.
            if !query_types.is_empty() && !query_types.iter().any(|t| matches!(*t, 1 | 28)) {
                bail!(
                    "fake-ip answers only A/AAAA queries; \
                     the rule needs an address-family type or no types"
                );
            }
            ResponseAction::FakeIp
        }
        RawDnsResponseAction::Address => {
            let address = raw
                .address
                .context("address action requires an IP address")?;
            // Same dead-rule shape: a static address emits only its own
            // family, so a `types` list without it can never fire.
            let (family, kind) = if address.is_ipv4() {
                (1, "A")
            } else {
                (28, "AAAA")
            };
            if !query_types.is_empty() && !query_types.contains(&family) {
                bail!(
                    "address {address} answers only {kind} queries; \
                     the rule needs that type or no types"
                );
            }
            ResponseAction::Address {
                address,
                ttl: raw.ttl.unwrap_or(60),
            }
        }
    };
    let keys = expand_policy_keys(&raw.matcher);
    if keys.is_empty() {
        bail!("match must contain a domain condition");
    }
    let mut matchers: Vec<NameserverPolicyMatcher> = Vec::new();
    // Prefixed keys (`geosite:`/`rule-set:`) get their own matchers; all
    // of a rule's plain-domain keys share one DomainTrie — the
    // nameserver-policy `domainTriePolicy` shape (see
    // `dns_parser::build_policy`) — instead of one trie per key.
    let mut domain_keys: Vec<&str> = Vec::new();
    let mut match_all = false;
    for key in &keys {
        if let Some(matcher) = build_matcher(key, geosite, providers)? {
            matchers.push(matcher);
        } else if key == "*" {
            match_all = true;
        } else {
            check_domain_key("dns.response-rules.match", key, true)?;
            domain_keys.push(key);
        }
    }
    if match_all {
        matchers.push(Arc::new(|_| true));
    } else if !domain_keys.is_empty() {
        let mut trie = DomainTrie::new();
        for key in domain_keys {
            trie.insert_overwrite(key, ());
        }
        matchers.push(Arc::new(move |host| trie.search(host).is_some()));
    }
    Ok(ResponseRule {
        matcher: Arc::new(move |host| matchers.iter().any(|matcher| matcher(host))),
        query_types,
        action,
    })
}

/// Compile a `geosite:`/`rule-set:` match key into a matcher of its own.
/// Returns `None` for a plain-domain key — the caller folds all of a
/// rule's domain keys into one shared `DomainTrie` arm.
fn build_matcher(
    key: &str,
    geosite: Option<&Arc<GeositeDB>>,
    providers: &HashMap<String, Arc<RuleProvider>>,
) -> Result<Option<NameserverPolicyMatcher>> {
    let lower = key.to_ascii_lowercase();
    if let Some(category) = lower.strip_prefix("geosite:") {
        if category.is_empty() {
            bail!("geosite category is empty");
        }
        let db = Arc::clone(geosite.context("geosite condition requires a loaded database")?);
        let category = category.to_owned();
        return Ok(Some(Arc::new(move |host| db.lookup(&category, host))));
    }
    if lower.starts_with("rule-set:") {
        let name = key["rule-set:".len()..].trim();
        if name.is_empty() {
            bail!("'rule-set:' key has an empty provider name");
        }
        let provider = providers
            .get(name)
            .with_context(|| format!("unknown rule-set: {name}"))?;
        if provider.behavior == RuleSetBehavior::IpCidr {
            bail!("rule-set '{name}' must use domain or classical behavior");
        }
        let provider = Arc::clone(provider);
        return Ok(Some(Arc::new(move |host| provider.matches_domain(host))));
    }
    if lower.contains(':') {
        bail!("unsupported match prefix: {key}");
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    #[test]
    fn response_rule_dependencies_are_discovered() {
        let raw = crate::parse_raw_yaml(
            r#"dns:
  enable: true
  response-rules:
    - {match: 'Geosite:CN,private@ads', action: nodata}
    - {match: '+.example.test,RULE-SET:Selected', action: refused}
"#,
        )
        .unwrap();
        assert!(crate::dns_policy_uses_geosite(&raw));
        let categories = crate::collect_dns_policy_geosite_categories(&raw);
        assert!(categories.contains("cn") && categories.contains("private"));
        assert!(crate::dns_parser::dns_needs_rule_providers(&raw));
    }
}
