use ipnet::IpNet;
use meow_common::auth::{AuthConfig, Credentials};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::warn;

/// Parse `authentication:` and `skip-auth-prefixes:` from raw config values
/// into an `AuthConfig`. Loopback prefixes (127.0.0.1/32 and ::1/128) are
/// always included in the skip list regardless of configuration.
pub fn parse_auth_config(
    authentication: Option<&[String]>,
    skip_auth_prefixes: Option<&[String]>,
) -> Result<AuthConfig, String> {
    let mut cred_map: HashMap<String, String> = HashMap::new();

    for entry in authentication.unwrap_or(&[]) {
        // mihomo templates spell "no credentials" as `authentication: [""]`
        // (the field is filled in only when a password is set), and mihomo
        // accepts that entry. An entry with nothing in it carries no
        // credential, so it is an empty list in disguise — not the typo the
        // Class A rule below is aimed at.
        if entry.trim().is_empty() {
            continue;
        }
        match entry.find(':') {
            None => {
                // Class A: malformed entry with no colon — hard parse error.
                // Upstream silently ignores; we diverge (ADR-0002 Class A) because
                // a missing colon is almost certainly a typo, not intent.
                return Err(format!(
                    "authentication: malformed entry {entry:?} — expected 'user:pass' format \
                    (Class A divergence from upstream: NOT silently ignored)"
                ));
            }
            Some(pos) => {
                let username = entry[..pos].to_string();
                let password = entry[pos + 1..].to_string();
                if username.is_empty() {
                    return Err(format!(
                        "authentication: malformed entry {entry:?} — username must not be empty"
                    ));
                }
                if password.is_empty() {
                    // Class B: empty password — warn-once and accept.
                    // Upstream accepts silently; we warn (ADR-0002 Class B).
                    warn!(
                        "authentication: entry {:?} has an empty password; accepted but \
                        this may be a configuration error \
                        (Class B divergence from upstream: warn-once)",
                        username
                    );
                }
                cred_map.insert(username, password);
            }
        }
    }

    // Build skip prefixes: start with loopbacks (always present), then add configured entries.
    let mut skip_prefixes: Vec<IpNet> = vec![
        IpNet::from_str("127.0.0.1/32").unwrap(),
        IpNet::from_str("::1/128").unwrap(),
    ];
    for cidr in skip_auth_prefixes.unwrap_or(&[]) {
        match IpNet::from_str(cidr) {
            Ok(net) => skip_prefixes.push(net),
            Err(e) => return Err(format!("skip-auth-prefixes: invalid CIDR {cidr:?}: {e}")),
        }
    }

    Ok(AuthConfig::new(
        Arc::new(Credentials::new(cred_map)),
        skip_prefixes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_auth(entries: &[&str]) -> AuthConfig {
        parse_auth_config(
            Some(
                &entries
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            None,
        )
        .unwrap()
    }

    #[test]
    fn credentials_verify_table() {
        let cfg = make_auth(&["alice:hunter2"]);
        // (case label, username, password, expected)
        let cases: &[(&str, &str, &str, bool)] = &[
            ("correct credentials", "alice", "hunter2", true),
            ("wrong password", "alice", "wrong", false),
            ("unknown user", "bob", "hunter2", false),
        ];
        for (label, username, password, expected) in cases {
            assert_eq!(
                cfg.credentials.verify(username, password),
                *expected,
                "case {label}: verify({username:?}, {password:?}) should be {expected}"
            );
        }
    }

    #[test]
    fn credentials_verify_constant_time_uses_subtle() {
        let cfg = make_auth(&["alice:abc"]);
        assert!(cfg.credentials.verify("alice", "abc"));
        assert!(!cfg.credentials.verify("alice", "abd"));
        assert!(!cfg.credentials.verify("alice", "ab"));
        assert!(!cfg.credentials.verify("alice", "abcd"));
    }

    #[test]
    fn skip_prefixes_loopback_always_skipped() {
        // No skip-auth-prefixes configured — loopback is still skipped.
        let cfg = parse_auth_config(Some(&["alice:pass".to_string()]), None).unwrap();
        assert!(cfg.should_skip(&"127.0.0.1".parse().unwrap()));
        assert!(cfg.should_skip(&"::1".parse().unwrap()));
        assert!(!cfg.should_skip(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn parse_authentication_valid() {
        let cfg = make_auth(&["alice:hunter2", "bob:s3cr3t"]);
        assert!(cfg.credentials.verify("alice", "hunter2"));
        assert!(cfg.credentials.verify("bob", "s3cr3t"));
    }

    #[test]
    fn parse_authentication_empty_entry_is_ignored() {
        // The stock mihomo template ships `authentication: [""]`; treating it
        // as a malformed entry made the whole config refuse to load.
        let blank: Vec<String> = vec![String::new(), "   ".to_string()];
        let cfg = parse_auth_config(Some(&blank), None).unwrap();
        assert!(!cfg.credentials.verify("", ""));

        let mixed: Vec<String> = vec![String::new(), "alice:hunter2".to_string()];
        let cfg = parse_auth_config(Some(&mixed), None).unwrap();
        assert!(cfg.credentials.verify("alice", "hunter2"));
    }

    #[test]
    fn parse_authentication_malformed_no_colon() {
        // Class A: hard error, NOT silent ignore.
        let err = parse_auth_config(Some(&["userpassword".to_string()]), None).unwrap_err();
        assert!(
            err.contains("malformed"),
            "expected malformed error, got: {err}"
        );
    }

    #[test]
    fn parse_authentication_empty_username_errors() {
        let err = parse_auth_config(Some(&[":pass".to_string()]), None).unwrap_err();
        assert!(
            err.contains("username"),
            "expected username error, got: {err}"
        );
    }

    #[test]
    fn parse_authentication_empty_password_accepted() {
        // Class B: empty password warns but is accepted.
        let cfg = parse_auth_config(Some(&["user:".to_string()]), None).unwrap();
        assert!(cfg.credentials.verify("user", ""));
        assert!(!cfg.credentials.verify("user", "x"));
    }

    #[test]
    fn parse_skip_auth_prefixes_valid_cidr() {
        let cfg = parse_auth_config(
            None,
            Some(&["192.168.0.0/24".to_string(), "10.0.0.0/8".to_string()]),
        )
        .unwrap();
        assert!(cfg.should_skip(&"192.168.0.5".parse().unwrap()));
        assert!(cfg.should_skip(&"10.1.2.3".parse().unwrap()));
        assert!(!cfg.should_skip(&"172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_skip_auth_prefixes_invalid_cidr() {
        let err = parse_auth_config(None, Some(&["not-a-cidr".to_string()])).unwrap_err();
        assert!(err.contains("invalid CIDR"), "got: {err}");
    }
}
