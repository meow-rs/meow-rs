//! Providers a lenient build leaves out, held for the logbook until the
//! build is committed.

/// Providers a lenient build left out of its config — a definition that
/// does not construct, a payload that does not parse, a `proxy:` that does
/// not resolve — with why. The commit that installs the build records them
/// in the logbook ([`Self::record`]), not the build: startup builds its
/// providers more than once, and a rejected candidate (`PUT /configs`)
/// never takes effect, so recording while building would count a failure
/// more than once, or one that never happened to the running config.
#[derive(Debug, Default)]
pub struct DroppedProviders {
    rule: Vec<(String, String)>,
    proxy: Vec<(String, String)>,
}

impl DroppedProviders {
    pub(crate) fn rule(&mut self, name: &str, error: String) {
        self.rule.push((name.to_owned(), error));
    }

    pub(crate) fn proxy(&mut self, name: &str, error: String) {
        self.proxy.push((name.to_owned(), error));
    }

    /// Take the rule providers `other` left out.
    pub(crate) fn take_rule(&mut self, other: &mut Self) {
        self.rule.append(&mut other.rule);
    }

    pub fn is_empty(&self) -> bool {
        self.rule.is_empty() && self.proxy.is_empty()
    }

    /// Record each as its provider's failed update. Call once the build is
    /// committed.
    pub fn record(&self) {
        for (name, error) in &self.rule {
            crate::rule_provider::record_failure(name, error);
        }
        for (name, error) in &self.proxy {
            crate::proxy_provider::record_failure(name, error);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::TestLogbook;
    use meow_common::logbook::{kind, Level};

    const CONFIG: &str = "\
proxy-providers:
  dropped-proxy-provider:
    type: bogus
rule-providers:
  dropped-rule-provider:
    type: bogus
    behavior: domain
rules:
  - MATCH,DIRECT
";

    #[tokio::test]
    async fn a_lenient_build_records_what_it_left_out_once_committed() {
        let book = TestLogbook::install();
        let recorded = || {
            [
                book.entries("dropped-rule-provider"),
                book.entries("dropped-proxy-provider"),
            ]
        };

        // Startup builds its providers more than once; the commit records once.
        let config = crate::load_config_from_str(CONFIG).await.unwrap();
        assert!(!config.dropped_providers.is_empty());
        assert_eq!(recorded(), [vec![], vec![]]);

        // A candidate never committed records nothing.
        let raw = crate::parse_raw_yaml(CONFIG).unwrap();
        let candidate = crate::rebuild_from_raw(&raw).unwrap();
        assert!(!candidate.dropped_providers.is_empty());
        drop(candidate);
        assert_eq!(recorded(), [vec![], vec![]]);

        config.dropped_providers.record();
        let [rule, proxy] = recorded();
        for (entries, kind) in [
            (rule, kind::RULE_PROVIDER_UPDATE),
            (proxy, kind::PROXY_PROVIDER_UPDATE),
        ] {
            assert_eq!(entries.len(), 1, "{entries:?}");
            let entry = &entries[0];
            assert_eq!(
                (entry.kind.as_str(), entry.level, entry.count),
                (kind, Level::Error, 1)
            );
            assert!(entry.message.contains("bogus"), "{}", entry.message);
        }
    }
}
