use crate::raw::{RawConfig, RawProxyGroup};
use serde_yaml::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Result of parsing a subscription YAML.
pub struct SubscriptionData {
    pub proxies: Vec<HashMap<String, Value>>,
    pub proxy_groups: Vec<RawProxyGroup>,
    pub rules: Vec<String>,
}

/// Section totals after a subscription apply.
#[derive(Debug, Default, Clone, Copy)]
pub struct SubscriptionCounts {
    pub proxies: usize,
    pub proxy_groups: usize,
    pub rules: usize,
}

fn proxy_entry_name(entry: &HashMap<String, Value>) -> Option<&str> {
    entry.get("name").and_then(Value::as_str)
}

/// Remove each string in `applied` from `rules` at most once (multiset
/// subtraction): a rule the user also wrote by hand keeps its own copy.
fn subtract_rules(rules: &mut Vec<String>, applied: &[String]) {
    if applied.is_empty() {
        return;
    }
    let mut pending: HashMap<&str, usize> = HashMap::new();
    for r in applied {
        *pending.entry(r.as_str()).or_default() += 1;
    }
    rules.retain(|r| match pending.get_mut(r.as_str()) {
        Some(remaining) if *remaining > 0 => {
            *remaining -= 1;
            false
        }
        _ => true,
    });
}

/// Merge a fetched payload into `raw` as subscription `name`'s
/// contribution, replacing only the entries that subscription contributed
/// on its previous apply (tracked in its `applied-*` fields). Local
/// `proxies:`/`proxy-groups:`/`rules:` and sibling subscriptions' content
/// survive (issue #640); entries the remote stopped shipping are removed
/// via the tracked set, so upstream deletions still propagate.
///
/// `proxies`/`proxy-groups` merge by name — a remote name shadows the
/// kept entry (remote wins). `rules` has no key to merge on, so the
/// payload's rule strings are prepended ahead of the kept rules: the
/// subscription's own routing table keeps working even when the local
/// table ends in a `MATCH,` rule. A payload that ships no rules vacates
/// the subscription's previous rule contribution.
///
/// Must run on the candidate inside the `CONFIG_MUTATION` lane — it reads
/// and rewrites `raw.subscriptions` (the apply also releases names a
/// sibling subscription now claims, so `DELETE` of that sibling does not
/// remove this subscription's nodes).
pub fn apply_subscription(
    raw: &mut RawConfig,
    name: &str,
    fetched: SubscriptionData,
) -> Option<SubscriptionCounts> {
    let remote_proxies: HashSet<String> = fetched
        .proxies
        .iter()
        .filter_map(|p| proxy_entry_name(p).map(str::to_string))
        .collect();
    let remote_groups: HashSet<String> = fetched
        .proxy_groups
        .iter()
        .map(|g| g.name.clone())
        .collect();

    let subs = raw.subscriptions.get_or_insert_with(Vec::new);
    // Locate the entry first so a missing name exits before any sibling
    // tracking is released.
    let idx = subs.iter().position(|s| s.name == name)?;
    // Names tracked by ANY subscription — snapshot before the sibling
    // release below, so a remote name in this union is either this
    // subscription's own previous contribution or a sibling's (an
    // ownership transfer), NOT a genuinely-local entry. Only names
    // outside the union shadow local content and deserve a warning
    // (issue #640 review).
    let mut tracked_proxies: HashSet<String> = HashSet::new();
    let mut tracked_groups: HashSet<String> = HashSet::new();
    for s in subs.iter() {
        tracked_proxies.extend(s.applied_proxies.iter().cloned());
        tracked_groups.extend(s.applied_groups.iter().cloned());
    }
    // Ownership transfer for the name-keyed sections: a proxy/group name
    // the refreshed payload ships now belongs to this subscription —
    // release it from every sibling's applied set so the sibling's
    // delete does not remove this subscription's fresh node. Rules are
    // NOT transferred: they are a multiset, and shared strings are
    // already handled correctly by per-subscription `subtract_rules`
    // counts — stripping a sibling's tracked copies here would leak the
    // strings it applied (issue #640 review).
    for s in subs
        .iter_mut()
        .enumerate()
        .filter_map(|(i, s)| (i != idx).then_some(s))
    {
        s.applied_proxies.retain(|n| !remote_proxies.contains(n));
        s.applied_groups.retain(|n| !remote_groups.contains(n));
    }
    let sub = &mut subs[idx];

    let prev_proxies: HashSet<String> = std::mem::take(&mut sub.applied_proxies)
        .into_iter()
        .collect();
    let prev_groups: HashSet<String> = std::mem::take(&mut sub.applied_groups)
        .into_iter()
        .collect();
    let prev_rules = std::mem::take(&mut sub.applied_rules);

    // Proxies: keep entries neither contributed by this subscription last
    // time nor shadowed by the fresh payload; append the remote nodes.
    let mut proxies: Vec<HashMap<String, Value>> = raw.proxies.take().unwrap_or_default();
    proxies.retain(|p| {
        let Some(n) = proxy_entry_name(p) else {
            return true;
        };
        if remote_proxies.contains(n) && !tracked_proxies.contains(n) {
            tracing::warn!(
                "subscription '{name}': remote node '{n}' replaces a local \
                 proxy of the same name — the local definition is not \
                 restored when the remote drops it"
            );
        }
        !prev_proxies.contains(n) && !remote_proxies.contains(n)
    });
    proxies.extend(fetched.proxies);
    raw.proxies = Some(proxies);

    let mut groups: Vec<RawProxyGroup> = raw.proxy_groups.take().unwrap_or_default();
    groups.retain(|g| {
        if remote_groups.contains(&g.name) && !tracked_groups.contains(&g.name) {
            tracing::warn!(
                "subscription '{name}': remote group '{}' replaces a local \
                 proxy-group of the same name — the local definition is not \
                 restored when the remote drops it",
                g.name
            );
        }
        !prev_groups.contains(&g.name) && !remote_groups.contains(&g.name)
    });
    groups.extend(fetched.proxy_groups);
    raw.proxy_groups = Some(groups);

    // Rules: drop the subscription's previous contribution (multiset
    // subtraction), then prepend the fresh remote table. The applied set
    // stores the contributed strings verbatim — duplicates included — so
    // the next apply removes exactly what was added.
    let mut rules: Vec<String> = raw.rules.take().unwrap_or_default();
    subtract_rules(&mut rules, &prev_rules);
    sub.applied_rules = fetched.rules;
    let mut merged = sub.applied_rules.clone();
    merged.extend(rules);
    raw.rules = Some(merged);

    // Sorted for deterministic written-back YAML — the sets iterate in
    // arbitrary order otherwise and churn the save file every refresh.
    sub.applied_proxies = remote_proxies.into_iter().collect();
    sub.applied_proxies.sort();
    sub.applied_groups = remote_groups.into_iter().collect();
    sub.applied_groups.sort();

    Some(SubscriptionCounts {
        proxies: raw.proxies.as_ref().map_or(0, Vec::len),
        proxy_groups: raw.proxy_groups.as_ref().map_or(0, Vec::len),
        rules: raw.rules.as_ref().map_or(0, Vec::len),
    })
}

/// Remove `name`'s tracked contribution from `raw` — the inverse of
/// [`apply_subscription`], run by `DELETE /api/subscriptions/{name}`.
/// Only entries the subscription actually applied are dropped; local
/// proxies, groups, and rules it never declared stay (issue #640). The
/// `subscriptions` entry itself is retained for the caller to remove.
pub fn remove_subscription_contribution(raw: &mut RawConfig, name: &str) {
    let Some(sub) = raw
        .subscriptions
        .as_ref()
        .and_then(|subs| subs.iter().find(|s| s.name == name))
    else {
        return;
    };
    let prev_proxies: HashSet<String> = sub.applied_proxies.iter().cloned().collect();
    let prev_groups: HashSet<String> = sub.applied_groups.iter().cloned().collect();
    let prev_rules = sub.applied_rules.clone();

    if let Some(proxies) = raw.proxies.as_mut() {
        proxies.retain(|p| !proxy_entry_name(p).is_some_and(|n| prev_proxies.contains(n)));
    }
    if let Some(groups) = raw.proxy_groups.as_mut() {
        groups.retain(|g| !prev_groups.contains(&g.name));
    }
    if let Some(rules) = raw.rules.as_mut() {
        subtract_rules(rules, &prev_rules);
    }

    // Clear the entry's tracking too: the sole caller deletes the entry
    // next, but a future caller that keeps it must not let stale sets
    // claim same-named local entries on the next apply.
    if let Some(sub) = raw
        .subscriptions
        .as_mut()
        .and_then(|subs| subs.iter_mut().find(|s| s.name == name))
    {
        sub.applied_proxies.clear();
        sub.applied_groups.clear();
        sub.applied_rules.clear();
    }
}

/// Reconcile `applied-*` claims against physical presence after a
/// non-subscription edit of the sections (`PUT /configs`, rule/group
/// CRUD). Claims must never outlive the entries they name — a stale
/// claim would otherwise let a later apply/`DELETE` eat a user-owned
/// entry re-created under the same name (issue #640 review). Rules are
/// clamped as a multiset: each subscription keeps at most as many
/// claims on a string as physical copies remain.
pub fn reconcile_contribution_claims(raw: &mut RawConfig) {
    let Some(subs) = raw.subscriptions.as_mut() else {
        return;
    };
    if subs.is_empty() {
        return;
    }
    let present_proxies: HashSet<String> = raw
        .proxies
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|p| proxy_entry_name(p).map(str::to_string))
        .collect();
    let present_groups: HashSet<&str> = raw
        .proxy_groups
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|g| g.name.as_str())
        .collect();
    let mut available_rules: HashMap<&str, usize> = HashMap::new();
    for r in raw.rules.as_deref().unwrap_or(&[]) {
        *available_rules.entry(r.as_str()).or_default() += 1;
    }
    for s in subs.iter_mut() {
        s.applied_proxies.retain(|n| present_proxies.contains(n));
        s.applied_groups
            .retain(|n| present_groups.contains(n.as_str()));
        s.applied_rules
            .retain(|r| match available_rules.get_mut(r.as_str()) {
                Some(n) if *n > 0 => {
                    *n -= 1;
                    true
                }
                _ => false,
            });
    }
}

/// Fetch a Clash YAML subscription and extract proxies, groups, and rules.
/// `strict` (issue #533) turns payload shape defects — a `proxy-groups`
/// section that fails to deserialize, a `proxies` entry that isn't a
/// mapping — into hard errors instead of warn-and-skip, so a garbled
/// subscription cannot silently empty every group under `strict: true`.
/// `download_proxy` routes the fetch through a resolved proxy/group — the
/// subscription's `proxy:` field, resolved by the caller against the live
/// route map (issue #625).
pub async fn fetch_subscription(
    url: &str,
    strict: bool,
    download_proxy: Option<&Arc<dyn meow_common::Proxy>>,
) -> Result<SubscriptionData, anyhow::Error> {
    let bytes = crate::internal_http::fetch(url, download_proxy, &[]).await?;
    let text = String::from_utf8(bytes)
        .map_err(|e| PayloadDefect(anyhow::anyhow!("subscription body is not UTF-8: {e}")))?;
    parse_subscription_yaml(&text, strict)
        .map_err(PayloadDefect)
        .map_err(Into::into)
}

/// Marks a subscription *payload* defect (UTF-8/YAML/shape, incl. strict
/// mode) as opposed to a transport failure — re-fetching the same URL
/// reproduces the same error, so periodic refreshers stamp `last_updated`
/// and honor `interval` instead of retrying every pass (issue #533 review).
/// Reachable via `err.downcast_ref::<PayloadDefect>()` on the
/// `anyhow::Error` [`fetch_subscription`] returns.
#[derive(Debug)]
pub struct PayloadDefect(pub anyhow::Error);

impl std::fmt::Display for PayloadDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for PayloadDefect {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Parse a Clash YAML string and extract proxies, proxy-groups, and rules.
pub fn parse_subscription_yaml(
    text: &str,
    strict: bool,
) -> Result<SubscriptionData, anyhow::Error> {
    if !crate::yaml_within_depth(text) {
        return Err(anyhow::anyhow!(
            "subscription YAML exceeds the nesting-depth limit"
        ));
    }
    let mut root: Value =
        serde_yaml::from_str(text).map_err(|e| anyhow::anyhow!("YAML parse error: {e}"))?;
    // Expand `<<: *anchor` merge keys so subscriptions that share anchor
    // blocks (rule-anchor patterns, common in upstream mihomo configs) parse.
    root.apply_merge()
        .map_err(|e| anyhow::anyhow!("YAML merge expand error: {e}"))?;
    let mapping = root
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("subscription root is not a mapping"))?;

    // Extract proxies
    let proxies_key = Value::String("proxies".to_string());
    let proxies_val = mapping.get(&proxies_key).ok_or_else(|| {
        let keys: Vec<String> = mapping
            .keys()
            .filter_map(|k| k.as_str().map(std::string::ToString::to_string))
            .collect();
        anyhow::anyhow!("subscription missing 'proxies' key; found keys: {keys:?}")
    })?;
    let proxies_seq = proxies_val
        .as_sequence()
        .ok_or_else(|| anyhow::anyhow!("'proxies' is not a sequence"))?;

    let mut proxies = Vec::new();
    for proxy in proxies_seq {
        if let Value::Mapping(map) = proxy {
            let hm: HashMap<String, Value> = map
                .iter()
                .filter_map(|(k, v)| k.as_str().map(|ks| (ks.to_string(), v.clone())))
                .collect();
            // Subscription content is remote-controlled and lands in the
            // trusted `proxies:` list, where an `ss` node's `plugin:` would
            // reach `Command::new` — drop external-SIP003 nodes here
            // (issue #513). No opt-in: a local plugin belongs in local
            // config.
            if crate::proxy_parser::node_selects_external_plugin(&hm) {
                let name = hm.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let plugin = hm.get("plugin").and_then(|v| v.as_str()).unwrap_or("");
                tracing::warn!(
                    "subscription node '{name}': dropping external SIP003 plugin \
                     '{plugin}' (would spawn a local executable selected by \
                     remote content); declare the node in local config if \
                     intended"
                );
                continue;
            }
            // A proxy entry without a string `name` cannot be keyed,
            // tracked in `applied-proxies`, or removed on refresh/delete —
            // it would re-append on every apply and accumulate forever
            // (issue #640 review). Same shape-defect gating as below.
            if !hm.get("name").is_some_and(|v| v.as_str().is_some()) {
                if strict {
                    return Err(anyhow::anyhow!(
                        "subscription 'proxies' entry has no string 'name' \
                         (strict mode): {hm:?}"
                    ));
                }
                tracing::warn!("subscription 'proxies' entry has no string 'name'; skipping");
                continue;
            }
            proxies.push(hm);
        } else {
            // A non-mapping `proxies:` entry is a payload shape defect — it
            // cannot be interpreted as a node. Silent-skip under strict would
            // let a garbled subscription drop nodes unnoticed (issue #533).
            if strict {
                return Err(anyhow::anyhow!(
                    "subscription 'proxies' entry is not a mapping (strict mode): {proxy:?}"
                ));
            }
            tracing::warn!("subscription 'proxies' entry is not a mapping; skipping");
        }
    }

    // Extract proxy-groups. Deserialize per entry so one malformed group
    // doesn't wipe the whole list: strict fails the subscription, lenient
    // warn-skips the entry — a whole-section `from_value` failure used to
    // silently yield `[]`, emptying every group on commit (issue #533).
    let groups_key = Value::String("proxy-groups".to_string());
    let mut proxy_groups: Vec<RawProxyGroup> = Vec::new();
    match mapping.get(&groups_key) {
        None => {}
        Some(v) => {
            let Some(seq) = v.as_sequence() else {
                return Err(anyhow::anyhow!(
                    "subscription 'proxy-groups' is not a sequence"
                ));
            };
            for entry in seq {
                match serde_yaml::from_value::<RawProxyGroup>(entry.clone()) {
                    Ok(group) => proxy_groups.push(group),
                    Err(e) if strict => {
                        return Err(anyhow::anyhow!(
                            "subscription 'proxy-groups' entry failed to parse \
                             (strict mode): {e}"
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "subscription 'proxy-groups' entry failed to parse; \
                             skipping: {e}"
                        );
                    }
                }
            }
        }
    }

    // Extract rules — same shape-defect gating as proxies/groups: a
    // non-sequence `rules:` or a non-string entry is a payload defect, not a
    // transient condition (issue #533).
    let rules_key = Value::String("rules".to_string());
    let mut rules: Vec<String> = Vec::new();
    match mapping.get(&rules_key) {
        None => {}
        Some(v) => {
            let Some(seq) = v.as_sequence() else {
                return Err(anyhow::anyhow!("subscription 'rules' is not a sequence"));
            };
            for entry in seq {
                match entry.as_str() {
                    Some(rule) => rules.push(rule.to_string()),
                    None if strict => {
                        return Err(anyhow::anyhow!(
                            "subscription 'rules' entry is not a string \
                             (strict mode): {entry:?}"
                        ));
                    }
                    None => {
                        tracing::warn!("subscription 'rules' entry is not a string; skipping");
                    }
                }
            }
        }
    }

    Ok(SubscriptionData {
        proxies,
        proxy_groups,
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::RawSubscription;
    use std::sync::Mutex;

    fn proxy_entry(name: &str) -> HashMap<String, Value> {
        HashMap::from([
            ("name".to_string(), Value::String(name.to_string())),
            ("type".to_string(), Value::String("http".to_string())),
        ])
    }

    fn group(name: &str) -> RawProxyGroup {
        serde_yaml::from_str(&format!("name: {name}\ntype: select\n")).unwrap()
    }

    fn sub(name: &str) -> RawSubscription {
        RawSubscription {
            name: name.to_string(),
            url: "http://x/sub".to_string(),
            interval: None,
            last_updated: None,
            proxy: None,
            applied_proxies: Vec::new(),
            applied_groups: Vec::new(),
            applied_rules: Vec::new(),
        }
    }

    fn raw_with_sub(sub: RawSubscription) -> RawConfig {
        RawConfig {
            subscriptions: Some(vec![sub]),
            ..Default::default()
        }
    }

    fn proxy_names(raw: &RawConfig) -> Vec<String> {
        raw.proxies
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|p| proxy_entry_name(p).map(str::to_string))
            .collect()
    }

    /// Issue #640: a proxies-only payload must not wipe the local helper
    /// proxy, groups, or rule table — the remote node joins alongside.
    #[test]
    fn apply_proxies_only_payload_keeps_local_sections() {
        let mut raw = raw_with_sub(sub("s"));
        raw.proxies = Some(vec![proxy_entry("selfhop")]);
        raw.proxy_groups = Some(vec![group("local-g")]);
        raw.rules = Some(vec!["DOMAIN,x.test,REJECT".into(), "MATCH,selfhop".into()]);

        let counts = apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: vec![proxy_entry("node-1")],
                proxy_groups: Vec::new(),
                rules: Vec::new(),
            },
        )
        .unwrap();

        assert_eq!(proxy_names(&raw), vec!["selfhop", "node-1"]);
        assert_eq!(raw.proxy_groups.as_deref().unwrap()[0].name, "local-g");
        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &[
                "DOMAIN,x.test,REJECT".to_string(),
                "MATCH,selfhop".to_string()
            ]
        );
        assert_eq!(counts.proxies, 2);
        assert_eq!(counts.proxy_groups, 1);
        assert_eq!(counts.rules, 2);

        let s = &raw.subscriptions.as_ref().unwrap()[0];
        assert_eq!(s.applied_proxies, vec!["node-1".to_string()]);
        assert!(s.applied_groups.is_empty());
        assert!(s.applied_rules.is_empty());
    }

    /// A refresh replaces only the subscription's own contribution:
    /// remote nodes that vanished are dropped, fresh ones join, local
    /// entries are untouched — and a remote name shadowing a local entry
    /// wins.
    #[test]
    fn apply_replaces_only_tracked_contribution() {
        let mut raw = raw_with_sub(sub("s"));
        raw.proxies = Some(vec![proxy_entry("selfhop")]);
        apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: vec![proxy_entry("node-1")],
                proxy_groups: Vec::new(),
                rules: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(proxy_names(&raw), vec!["selfhop", "node-1"]);

        // Refresh: remote dropped node-1, ships node-2 instead.
        apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: vec![proxy_entry("node-2")],
                proxy_groups: Vec::new(),
                rules: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            proxy_names(&raw),
            vec!["selfhop", "node-2"],
            "the stale remote node must be removed via the tracked set"
        );
        assert_eq!(
            raw.subscriptions.as_ref().unwrap()[0].applied_proxies,
            vec!["node-2".to_string()]
        );
    }

    /// Remote rules prepend ahead of the kept local table so the
    /// subscription's routing still works next to a local `MATCH,` tail;
    /// a later payload without rules vacates the remote contribution
    /// while leaving the local table intact.
    #[test]
    fn apply_prepends_remote_rules_then_vacates() {
        let mut raw = raw_with_sub(sub("s"));
        raw.rules = Some(vec!["MATCH,selfhop".into()]);

        apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: Vec::new(),
                proxy_groups: Vec::new(),
                rules: vec!["DOMAIN,sub.example,node-1".into(), "MATCH,node-1".into()],
            },
        )
        .unwrap();
        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &[
                "DOMAIN,sub.example,node-1".to_string(),
                "MATCH,node-1".to_string(),
                "MATCH,selfhop".to_string(),
            ]
        );

        // Next payload ships no rules: the remote table vacates, the
        // local rule survives.
        apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: Vec::new(),
                proxy_groups: Vec::new(),
                rules: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &["MATCH,selfhop".to_string()]
        );
        assert!(raw.subscriptions.as_ref().unwrap()[0]
            .applied_rules
            .is_empty());
    }

    /// A local rule string identical to a remote one keeps ONE copy: the
    /// multiset subtraction removes only the subscription's contribution,
    /// not the user's own.
    #[test]
    fn apply_rules_multiset_subtraction_keeps_user_duplicate() {
        let mut raw = raw_with_sub(sub("s"));
        raw.rules = Some(vec!["MATCH,DIRECT".into()]);
        apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: Vec::new(),
                proxy_groups: Vec::new(),
                rules: vec!["MATCH,DIRECT".into()],
            },
        )
        .unwrap();
        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &["MATCH,DIRECT".to_string(), "MATCH,DIRECT".to_string()]
        );

        apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: Vec::new(),
                proxy_groups: Vec::new(),
                rules: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &["MATCH,DIRECT".to_string()],
            "the user's own duplicate must survive the contribution removal"
        );
    }

    /// Two subscriptions share the config: a refresh claiming a name the
    /// sibling contributed transfers ownership, so deleting the sibling
    /// does not remove the now-shared node.
    #[test]
    fn apply_transfers_ownership_of_sibling_names() {
        let mut raw = raw_with_sub(sub("a"));
        raw.subscriptions.as_mut().unwrap().push(sub("b"));
        apply_subscription(
            &mut raw,
            "a",
            SubscriptionData {
                proxies: vec![proxy_entry("shared")],
                proxy_groups: Vec::new(),
                rules: Vec::new(),
            },
        )
        .unwrap();
        apply_subscription(
            &mut raw,
            "b",
            SubscriptionData {
                proxies: vec![proxy_entry("shared"), proxy_entry("b-only")],
                proxy_groups: Vec::new(),
                rules: Vec::new(),
            },
        )
        .unwrap();

        let subs = raw.subscriptions.as_ref().unwrap();
        assert!(
            subs.iter()
                .find(|s| s.name == "a")
                .unwrap()
                .applied_proxies
                .is_empty(),
            "b's claim must release the name from a's applied set"
        );
        let mut b_applied = subs
            .iter()
            .find(|s| s.name == "b")
            .unwrap()
            .applied_proxies
            .clone();
        b_applied.sort();
        assert_eq!(b_applied, vec!["b-only".to_string(), "shared".to_string()]);
        assert_eq!(proxy_names(&raw), vec!["shared", "b-only"]);

        remove_subscription_contribution(&mut raw, "a");
        assert_eq!(proxy_names(&raw), vec!["shared", "b-only"]);
        remove_subscription_contribution(&mut raw, "b");
        assert!(proxy_names(&raw).is_empty());
    }

    /// Two subscriptions shipping the same rule string both track their
    /// own copy — rule strings are a multiset, so ownership stays shared
    /// (no transfer): each delete removes exactly one copy.
    #[test]
    fn shared_rule_string_stays_tracked_by_both_subs() {
        let mut raw = raw_with_sub(sub("a"));
        raw.subscriptions.as_mut().unwrap().push(sub("b"));
        let payload = || SubscriptionData {
            proxies: Vec::new(),
            proxy_groups: Vec::new(),
            rules: vec!["DOMAIN,x.test,REJECT".into()],
        };
        apply_subscription(&mut raw, "a", payload()).unwrap();
        apply_subscription(&mut raw, "b", payload()).unwrap();

        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &[
                "DOMAIN,x.test,REJECT".to_string(),
                "DOMAIN,x.test,REJECT".to_string()
            ]
        );
        for name in ["a", "b"] {
            let s = raw
                .subscriptions
                .as_ref()
                .unwrap()
                .iter()
                .find(|s| s.name == name)
                .unwrap();
            assert_eq!(
                s.applied_rules,
                vec!["DOMAIN,x.test,REJECT".to_string()],
                "{name} must keep tracking its own copy — a transfer would \
                 leak the sibling's string on delete"
            );
        }

        remove_subscription_contribution(&mut raw, "a");
        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &["DOMAIN,x.test,REJECT".to_string()]
        );
        remove_subscription_contribution(&mut raw, "b");
        assert!(raw.rules.as_deref().unwrap_or_default().is_empty());
    }

    /// `proxies:` entries without a string `name` cannot be tracked or
    /// removed — the parser must drop them instead of letting them
    /// accumulate on every apply.
    #[test]
    fn parse_drops_nameless_proxy_entries() {
        let yaml = "proxies:\n  - {type: http, server: 127.0.0.1, port: 1}\n  - {name: ok, type: http, server: 127.0.0.1, port: 2}\n  - {name: 123, type: http, server: 127.0.0.1, port: 3}\n";
        let data = parse_subscription_yaml(yaml, false).expect("lenient");
        let names: Vec<&str> = data
            .proxies
            .iter()
            .filter_map(|p| p.get("name").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(names, vec!["ok"]);

        assert!(
            parse_subscription_yaml(yaml, true).is_err(),
            "strict must hard-error on a nameless proxies entry"
        );
    }

    /// `reconcile_contribution_claims` clamps `applied-*` to physical
    /// presence after a non-subscription edit — claims must not outlive
    /// the entries they name or a later apply/`DELETE` would eat a
    /// user-owned entry re-created under the same name.
    #[test]
    fn reconcile_clamps_claims_to_physical_presence() {
        let mut raw = raw_with_sub(sub("s"));
        apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: vec![proxy_entry("n1")],
                proxy_groups: vec![RawProxyGroup {
                    name: "g1".into(),
                    group_type: "select".into(),
                    proxies: Some(vec!["n1".into()]),
                    ..Default::default()
                }],
                rules: vec!["R1".into(), "R1".into()],
            },
        )
        .unwrap();
        raw.proxies.as_mut().unwrap().push(proxy_entry("local"));
        raw.rules.as_mut().unwrap().push("R1".into());
        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &["R1".to_string(), "R1".to_string(), "R1".to_string()]
        );

        // An admin deletes the group and one `R1` copy — both claims
        // must shrink to what physically remains.
        raw.proxy_groups.as_mut().unwrap().clear();
        raw.rules.as_mut().unwrap().remove(0);
        reconcile_contribution_claims(&mut raw);

        let s = &raw.subscriptions.as_ref().unwrap()[0];
        assert!(s.applied_groups.is_empty());
        assert_eq!(
            s.applied_rules,
            vec!["R1".to_string(), "R1".to_string()],
            "2 copies remain → the claim keeps 2 (first-come wins)"
        );
        assert_eq!(s.applied_proxies, vec!["n1".to_string()]);

        // Deleting both remaining copies releases the claim entirely.
        raw.rules.as_mut().unwrap().clear();
        raw.proxies.as_mut().unwrap().clear();
        reconcile_contribution_claims(&mut raw);
        let s = &raw.subscriptions.as_ref().unwrap()[0];
        assert!(s.applied_rules.is_empty());
        assert!(s.applied_proxies.is_empty());
    }

    /// `DELETE` drops only the tracked contribution — a subscription that
    /// never applied (legacy config) removes nothing.
    #[test]
    fn remove_contribution_is_surgical() {
        let mut raw = raw_with_sub(sub("s"));
        raw.proxies = Some(vec![proxy_entry("selfhop")]);
        raw.rules = Some(vec!["MATCH,selfhop".into()]);
        apply_subscription(
            &mut raw,
            "s",
            SubscriptionData {
                proxies: vec![proxy_entry("node-1")],
                proxy_groups: vec![group("g")],
                rules: vec!["MATCH,g".into()],
            },
        )
        .unwrap();

        remove_subscription_contribution(&mut raw, "s");
        assert_eq!(proxy_names(&raw), vec!["selfhop"]);
        assert!(raw.proxy_groups.as_deref().unwrap_or_default().is_empty());
        assert_eq!(
            raw.rules.as_deref().unwrap(),
            &["MATCH,selfhop".to_string()]
        );

        // Legacy entry (empty applied sets) — removal keeps everything.
        let mut raw = raw_with_sub(sub("legacy"));
        raw.proxies = Some(vec![proxy_entry("stale-remote")]);
        remove_subscription_contribution(&mut raw, "legacy");
        assert_eq!(proxy_names(&raw), vec!["stale-remote"]);
    }

    /// `Proxy` that records each `dial_tcp` target and dials the real
    /// destination — proves a subscription fetch transits the caller's
    /// resolved hop instead of going direct (issue #625). Mirrors the
    /// provider-side harness in `proxy_provider::tests`.
    struct PassthroughProxy {
        seen: Mutex<Vec<(String, u16)>>,
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for PassthroughProxy {
        fn name(&self) -> &str {
            "front"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            self.seen
                .lock()
                .unwrap()
                .push((m.host.to_string(), m.dst_port));
            let stream = tokio::net::TcpStream::connect((m.host.as_str(), m.dst_port))
                .await
                .map_err(meow_common::MeowError::Io)?;
            Ok(Box::new(stream))
        }
        async fn dial_udp(
            &self,
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            unimplemented!("no udp")
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for PassthroughProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    /// Serves `body` once per connection on a loop, returning the URL.
    async fn spawn_payload_server(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut sink = [0u8; 2048];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
            }
        });
        format!("http://{addr}/sub.yaml")
    }

    /// A subscription `proxy:` must carry the fetch through the resolved
    /// hop — a regression to a direct fetch leaves `seen` empty.
    #[tokio::test]
    async fn fetch_subscription_through_download_proxy() {
        let body = "proxies:\n  - {name: n1, type: direct}\n";
        let url = spawn_payload_server(body).await;
        let proxy = Arc::new(PassthroughProxy {
            seen: Mutex::new(Vec::new()),
            health: meow_common::ProxyHealth::new(),
        });
        let dyn_proxy = Arc::clone(&proxy) as Arc<dyn meow_common::Proxy>;
        let data = fetch_subscription(&url, false, Some(&dyn_proxy))
            .await
            .unwrap();
        assert_eq!(data.proxies.len(), 1);
        assert!(
            proxy
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|(host, _)| host == "127.0.0.1"),
            "the subscription fetch must reach the named hop"
        );
    }

    /// The direct path (`proxy:` absent/DIRECT resolves to `None`) still
    /// works and parses the payload.
    #[tokio::test]
    async fn fetch_subscription_direct() {
        let url = spawn_payload_server("proxies:\n  - {name: n1, type: direct}\n").await;
        let data = fetch_subscription(&url, false, None).await.unwrap();
        assert_eq!(data.proxies[0].get("name").unwrap(), "n1");
    }
}
