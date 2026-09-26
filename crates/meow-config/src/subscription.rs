use crate::raw::RawProxyGroup;
use serde_yaml::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Result of parsing a subscription YAML.
pub struct SubscriptionData {
    pub proxies: Vec<HashMap<String, Value>>,
    pub proxy_groups: Vec<RawProxyGroup>,
    pub rules: Vec<String>,
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
    use std::sync::Mutex;

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
