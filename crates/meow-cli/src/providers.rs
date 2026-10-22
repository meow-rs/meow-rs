//! Proxy and rule providers, and config subscriptions.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use anyhow::bail;
use hyper::Method;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::{encode, ApiError};
use crate::format::{self, Table};
use crate::proxies::ProxyInfo;
use crate::{print, print_json, Ctx, ProviderKind};

/// Updates fetch over the network, maybe through a proxy.
const FETCH_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
struct Providers<T> {
    providers: BTreeMap<String, T>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ProxyProvider {
    vehicle_type: String,
    /// Empty when the provider has no health check to run.
    test_url: String,
    proxies: Vec<ProxyInfo>,
    updated_at: Option<String>,
    subscription_info: Option<Usage>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct Usage {
    upload: u64,
    download: u64,
    total: u64,
    expire: i64,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RuleProvider {
    behavior: String,
    rule_count: usize,
    updated_at: String,
    vehicle_type: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Subscription {
    name: String,
    url: String,
    last_updated: Option<i64>,
    proxy_count: usize,
    group_count: usize,
    rule_count: usize,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Refreshed {
    proxy_count: usize,
    group_count: usize,
    rule_count: usize,
    persisted: bool,
}

pub async fn list(ctx: &Ctx) -> anyhow::Result<()> {
    let proxy = ctx.client.get("/providers/proxies").await?;
    let rule = ctx.client.get("/providers/rules").await?;
    if ctx.json {
        return print_json(&json!({ "proxy": proxy["providers"], "rule": rule["providers"] }));
    }
    let proxy: Providers<ProxyProvider> = serde_json::from_value(proxy)?;
    let rule: Providers<RuleProvider> = serde_json::from_value(rule)?;
    if proxy.providers.is_empty() && rule.providers.is_empty() {
        return print("no providers\n");
    }
    let mut table = Table::new(&["KIND", "VEHICLE", "ITEMS", "UPDATED", "NAME"]);
    for (name, provider) in proxy.providers {
        let mut label = name;
        if let Some(usage) = &provider.subscription_info {
            write!(label, "  ({})", usage_text(usage))?;
        }
        table.row(vec![
            "proxy".into(),
            provider.vehicle_type,
            provider.proxies.len().to_string(),
            provider
                .updated_at
                .as_deref()
                .map(format::time)
                .unwrap_or_default(),
            label,
        ]);
    }
    for (name, provider) in rule.providers {
        table.row(vec![
            format!("rule ({})", provider.behavior),
            provider.vehicle_type,
            provider.rule_count.to_string(),
            format::time(&provider.updated_at),
            name,
        ]);
    }
    print(&table.render())
}

pub async fn update(ctx: &Ctx, name: &str, kind: Option<ProviderKind>) -> anyhow::Result<()> {
    let kind = match kind {
        Some(kind) => kind,
        None => {
            let proxy: Providers<Value> =
                serde_json::from_value(ctx.client.get("/providers/proxies").await?)?;
            let rule: Providers<Value> =
                serde_json::from_value(ctx.client.get("/providers/rules").await?)?;
            match (
                proxy.providers.contains_key(name),
                rule.providers.contains_key(name),
            ) {
                (true, true) => bail!(
                    "a proxy and a rule provider are both named {name}: pass --kind proxy or \
                     --kind rule"
                ),
                (true, false) => ProviderKind::Proxy,
                (false, true) => ProviderKind::Rule,
                (false, false) => bail!("no provider is named {name}"),
            }
        }
    };
    let (path, label) = match kind {
        ProviderKind::Proxy => (format!("/providers/proxies/{}", encode(name)), "proxy"),
        ProviderKind::Rule => (format!("/providers/rules/{}", encode(name)), "rule"),
    };
    ctx.client
        .waiting_at_least(FETCH_TIMEOUT)
        .call(Method::PUT, &path, None)
        .await
        .map_err(without_urls)?;
    ctx.done(&format!("updated {label} provider {name}"))
}

pub async fn check(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let path = format!("/providers/proxies/{}", encode(name));
    let provider: ProxyProvider = serde_json::from_value(ctx.client.get(&path).await?)?;
    // meow answers 204 without testing anything then.
    if provider.test_url.is_empty() {
        bail!(
            "{name} has no health-check in the config, or it is disabled; test its nodes one \
             by one with `meow-cli proxy test`"
        );
    }
    ctx.client
        .waiting_at_least(FETCH_TIMEOUT)
        .call(Method::GET, &format!("{path}/healthcheck"), None)
        .await?;
    let answer = ctx.client.get(&path).await?;
    ctx.show(answer, |provider: ProxyProvider| {
        let mut table = Table::new(&["DELAY", "TYPE", "NAME"]);
        for proxy in provider.proxies {
            table.row(vec![
                proxy.delay_text(),
                proxy.proxy_type.clone(),
                proxy.name,
            ]);
        }
        Ok(table.render())
    })
}

/// Subscription URLs carry access tokens: both outputs show their host.
pub async fn subscription_list(ctx: &Ctx) -> anyhow::Result<()> {
    let mut answer = ctx.client.get("/api/subscriptions").await?;
    for entry in answer.as_array_mut().into_iter().flatten() {
        if let Some(url) = entry.get_mut("url") {
            *url = Value::String(url_host(url.as_str().unwrap_or_default()));
        }
    }
    ctx.show(answer, |subscriptions: Vec<Subscription>| {
        if subscriptions.is_empty() {
            return Ok("no subscriptions\n".into());
        }
        let mut table = Table::new(&["PROXIES", "GROUPS", "RULES", "UPDATED", "NAME"]);
        for subscription in subscriptions {
            table.row(vec![
                subscription.proxy_count.to_string(),
                subscription.group_count.to_string(),
                subscription.rule_count.to_string(),
                subscription
                    .last_updated
                    .map_or_else(|| "never".into(), format::unix_time),
                format!("{}  ({})", subscription.name, subscription.url),
            ]);
        }
        Ok(table.render())
    })
}

pub async fn subscription_update(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let path = format!("/api/subscriptions/{}/refresh", encode(name));
    let answer = ctx
        .client
        .waiting_at_least(FETCH_TIMEOUT)
        .call(Method::POST, &path, None)
        .await
        .map_err(without_urls)?
        .unwrap_or_default();
    ctx.show(answer, |refreshed: Refreshed| {
        let mut text = format!(
            "updated {name}: {} proxies, {} groups, {} rules",
            refreshed.proxy_count, refreshed.group_count, refreshed.rule_count
        );
        if !refreshed.persisted {
            text.push_str(" (in memory only: meow runs without a config file)");
        }
        text.push('\n');
        Ok(text)
    })
}

/// `12.3 GB of 200.0 GB used, until 2026-12-01`.
fn usage_text(usage: &Usage) -> String {
    let used = format::bytes(usage.upload + usage.download);
    let mut text = if usage.total > 0 {
        format!("{used} of {} used", format::bytes(usage.total))
    } else {
        format!("{used} used")
    };
    if usage.expire > 0 {
        let until = format::unix_time(usage.expire);
        text.push_str(", until ");
        text.push_str(until.split(' ').next().unwrap_or_default());
    }
    text
}

/// A failed fetch can quote the URL, access token and all: keep its host.
fn without_urls(error: anyhow::Error) -> anyhow::Error {
    match error.downcast::<ApiError>() {
        Ok(mut refused) => {
            refused.message = hide_urls(&refused.message);
            refused.into()
        }
        Err(error) => error,
    }
}

/// `text` with each `scheme://…` in it cut down by [`url_host`].
fn hide_urls(text: &str) -> String {
    let mut hidden = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let scheme = rest[..at]
            .bytes()
            .rev()
            .take_while(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(byte))
            .count();
        let end = rest[at..]
            .find(|c: char| c.is_whitespace() || "'\"`<>()".contains(c))
            .map_or(rest.len(), |len| at + len);
        hidden.push_str(&rest[..at - scheme]);
        hidden.push_str(&url_host(&rest[at - scheme..end]));
        rest = &rest[end..];
    }
    hidden.push_str(rest);
    hidden
}

/// `https://sub.example.com/…` for any URL: its scheme and host only.
fn url_host(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // Credentials before an `@` are as secret as the path.
    let host = host.rsplit('@').next().unwrap_or_default();
    if scheme.is_empty() {
        format!("{host}/…")
    } else {
        format!("{scheme}://{host}/…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_urls_keep_only_their_host() {
        assert_eq!(
            url_host("https://user:pw@sub.example.com/api/v1/client?token=abc"),
            "https://sub.example.com/…"
        );
        assert_eq!(url_host("sub.example.com/x"), "sub.example.com/…");
    }

    #[test]
    fn fetch_errors_lose_their_urls() {
        assert_eq!(
            hide_urls(
                "invalid URL 'https://sub.example.com/s?token=abc': x; \
                 too many redirects (> 5) starting from http://a.example/t/abc"
            ),
            "invalid URL 'https://sub.example.com/…': x; \
             too many redirects (> 5) starting from http://a.example/…"
        );
        assert_eq!(
            hide_urls("节点 https://x.example/k"),
            "节点 https://x.example/…"
        );
        assert_eq!(hide_urls("no url here"), "no url here");
    }

    #[test]
    fn usage_reads_as_used_of_total() {
        let usage = Usage {
            upload: 1024,
            download: 1024 * 1024,
            total: 200 * 1024 * 1024 * 1024,
            expire: 1_764_547_200,
        };
        assert_eq!(
            usage_text(&usage),
            "1.0 MB of 200.0 GB used, until 2025-12-01"
        );
    }
}
