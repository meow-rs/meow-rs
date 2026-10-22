//! Proxy groups and proxies: listing, selection and delay tests.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::time::Duration;

use anyhow::bail;
use hyper::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::{encode, refused_with, with_query};
use crate::format::{self, Table};
use crate::{print, print_json, Ctx, Probe};

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct ProxyInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub alive: bool,
    pub history: Vec<Delay>,
    pub udp: bool,
    /// Group-only: its members.
    pub all: Option<Vec<String>>,
    /// Group-only: the member it routes through.
    pub now: Option<String>,
    /// url-test / fallback: the pinned member, `""` when automatic.
    pub fixed: Option<String>,
    pub delay: Option<u16>,
    #[serde(rename = "provider-name")]
    pub provider_name: String,
}

#[derive(Deserialize, Default, Clone)]
pub struct Delay {
    pub time: String,
    pub delay: u16,
}

#[derive(Deserialize)]
struct ProxyMap {
    proxies: HashMap<String, ProxyInfo>,
}

/// `/proxies` with each entry as meow wrote it, by name.
#[derive(Deserialize)]
struct RawProxyMap {
    proxies: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct ProviderMap {
    providers: HashMap<String, ProviderMembers>,
}

#[derive(Deserialize)]
struct ProviderMembers {
    #[serde(default)]
    proxies: Vec<Value>,
}

#[derive(Deserialize)]
struct GroupName {
    name: String,
}

impl ProxyInfo {
    /// `45 ms`, `down`, or `-` before any successful test.
    pub fn delay_text(&self) -> String {
        match (self.alive, self.delay) {
            (false, _) => "down".into(),
            (true, Some(delay)) => format!("{delay} ms"),
            (true, None) => "-".into(),
        }
    }

    fn pinned(&self) -> Option<&str> {
        self.fixed.as_deref().filter(|fixed| !fixed.is_empty())
    }

    /// `Proxy -> HK 01`, with the pin when one is set.
    fn route_text(&self) -> String {
        let mut text = self.name.clone();
        if let Some(now) = &self.now {
            text.push_str(" -> ");
            text.push_str(now);
        }
        if let Some(pinned) = self.pinned() {
            if self.now.as_deref() == Some(pinned) {
                text.push_str(" (pinned)");
            } else {
                text.push_str(" (pinned to ");
                text.push_str(pinned);
                text.push_str(", which is down)");
            }
        }
        text
    }
}

pub async fn group_list(ctx: &Ctx) -> anyhow::Result<()> {
    let answer = ctx.client.get("/group").await?;
    if ctx.json {
        return print_json(&answer);
    }
    let groups: ProxyMap = serde_json::from_value(answer)?;
    let mut groups: Vec<ProxyInfo> = groups.proxies.into_values().collect();
    // Config order, as dashboards show it; GLOBAL and any group the config
    // list lacks go last, by name.
    let order: HashMap<String, usize> = match ctx.client.get("/api/proxy-groups").await {
        Ok(list) => serde_json::from_value::<Vec<GroupName>>(list)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(index, group)| (group.name, index))
            .collect(),
        Err(_) => HashMap::new(),
    };
    groups.sort_by(|a, b| {
        let rank = |group: &ProxyInfo| order.get(&group.name).copied().unwrap_or(usize::MAX);
        rank(a).cmp(&rank(b)).then_with(|| a.name.cmp(&b.name))
    });
    let mut table = Table::new(&["TYPE", "MEMBERS", "GROUP -> NOW"]);
    for group in &groups {
        let members = group.all.as_ref().map_or(0, Vec::len);
        table.row(vec![
            group.proxy_type.clone(),
            members.to_string(),
            group.route_text(),
        ]);
    }
    print(&table.render())
}

pub async fn group_show(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let answer = group(ctx, name).await?;
    if ctx.json {
        return print_json(&answer);
    }
    let group: ProxyInfo = serde_json::from_value(answer)?;
    let known = all_proxies(ctx).await?;
    let mut text = format!("{} ({})\n", group.route_text(), group.proxy_type);
    let mut table = Table::new(&["", "DELAY", "TYPE", "MEMBER"]);
    for member in group.all.iter().flatten() {
        let current = if group.now.as_deref() == Some(member.as_str()) {
            "*"
        } else {
            ""
        };
        let (delay, kind) = known
            .get(member.as_str())
            .map_or(("?".into(), String::new()), |proxy| {
                (proxy.delay_text(), proxy.proxy_type.clone())
            });
        table.row(vec![current.into(), delay, kind, member.clone()]);
    }
    text.push_str(&table.render());
    print(&text)
}

pub async fn group_select(ctx: &Ctx, name: &str, member: &str) -> anyhow::Result<()> {
    let path = format!("/proxies/{}", encode(name));
    ctx.client
        .call(Method::PUT, &path, Some(&json!({ "name": member })))
        .await?;
    show_route(ctx, name).await
}

pub async fn group_unfix(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let group: ProxyInfo = serde_json::from_value(group(ctx, name).await?)?;
    if group.fixed.is_none() {
        bail!(
            "{name} is a {} group: only url-test and fallback groups have an automatic \
             choice to return to",
            group.proxy_type
        );
    }
    let path = format!("/proxies/{}", encode(name));
    ctx.client.call(Method::DELETE, &path, None).await?;
    show_route(ctx, name).await
}

pub async fn group_test(ctx: &Ctx, name: &str, probe: &Probe) -> anyhow::Result<()> {
    let group: ProxyInfo = serde_json::from_value(group(ctx, name).await?)?;
    if let Some(pinned) = group.pinned() {
        eprintln!("note: the test clears {name}'s pin on {pinned}; it chooses on its own again");
    }
    let timeout = probe.probe_timeout.to_string();
    let path = with_query(
        &format!("/group/{}/delay", encode(name)),
        &[("url", Some(&probe.url)), ("timeout", Some(&timeout))],
    );
    let client = ctx.client.waiting_at_least(
        Duration::from_millis(probe.probe_timeout.into()) + Duration::from_secs(10),
    );
    // 504: no member passed before the deadline.
    let delays = match client.call(Method::GET, &path, None).await {
        Ok(answer) => answer.unwrap_or_else(|| json!({})),
        Err(e) if refused_with(&e) == Some(StatusCode::GATEWAY_TIMEOUT) => json!({}),
        Err(e) => return Err(e),
    };
    if ctx.json {
        return print_json(&delays);
    }
    let delays: BTreeMap<String, u16> = serde_json::from_value(delays)?;
    let mut rows: Vec<(Option<u16>, &String)> = group
        .all
        .iter()
        .flatten()
        .map(|member| (delays.get(member).copied(), member))
        .collect();
    // Fastest first, failures last; `None` sorts before `Some`, so flip it.
    rows.sort_by_key(|(delay, _)| (delay.is_none(), *delay));
    let mut table = Table::new(&["DELAY", "MEMBER"]);
    for (delay, member) in rows {
        let delay = delay.map_or_else(|| "failed".to_string(), |delay| format!("{delay} ms"));
        table.row(vec![delay, member.clone()]);
    }
    print(&table.render())
}

pub async fn proxy_list(ctx: &Ctx, filter: Option<&str>) -> anyhow::Result<()> {
    let route: RawProxyMap = serde_json::from_value(ctx.client.get("/proxies").await?)?;
    let mut entries: Vec<(Value, ProxyInfo)> = Vec::new();
    for raw in route.proxies.into_values() {
        let proxy: ProxyInfo = serde_json::from_value(raw.clone())?;
        if proxy.all.is_none() {
            entries.push((raw, proxy));
        }
    }
    for raw in provider_members(ctx).await? {
        let proxy: ProxyInfo = serde_json::from_value(raw.clone())?;
        entries.push((raw, proxy));
    }
    entries.retain(|(_, proxy)| {
        format::matches(
            filter,
            &[&proxy.name, &proxy.proxy_type, &proxy.provider_name],
        )
    });
    if ctx.json {
        let list: Vec<Value> = entries.into_iter().map(|(raw, _)| raw).collect();
        return print_json(&Value::Array(list));
    }
    let mut table = Table::new(&["TYPE", "UDP", "DELAY", "NAME"]);
    for (_, proxy) in entries {
        let mut name = proxy.name.clone();
        if !proxy.provider_name.is_empty() {
            write!(name, "  [{}]", proxy.provider_name)?;
        }
        table.row(vec![
            proxy.proxy_type.clone(),
            yes_no(proxy.udp).into(),
            proxy.delay_text(),
            name,
        ]);
    }
    print(&table.render())
}

pub async fn proxy_show(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let answer = ctx
        .client
        .get(&format!("/proxies/{}", encode(name)))
        .await?;
    ctx.show(answer, |proxy: ProxyInfo| {
        let mut text = String::new();
        writeln!(text, "{}", proxy.name)?;
        writeln!(text, "type      {}", proxy.proxy_type)?;
        writeln!(text, "udp       {}", yes_no(proxy.udp))?;
        if !proxy.provider_name.is_empty() {
            writeln!(text, "provider  {}", proxy.provider_name)?;
        }
        writeln!(text, "delay     {}", proxy.delay_text())?;
        if let Some(now) = &proxy.now {
            writeln!(text, "now       {now}")?;
        }
        if let Some(pinned) = proxy.pinned() {
            writeln!(text, "pinned    {pinned}")?;
        }
        if let Some(members) = &proxy.all {
            writeln!(text, "members   {}", members.join(", "))?;
        }
        for (index, test) in proxy.history.iter().enumerate() {
            let label = if index == 0 { "history" } else { "" };
            let delay = if test.delay == 0 {
                "failed".to_string()
            } else {
                format!("{} ms", test.delay)
            };
            writeln!(text, "{label:<8}  {}  {delay}", format::time(&test.time))?;
        }
        Ok(text)
    })
}

pub async fn proxy_test(ctx: &Ctx, name: &str, probe: &Probe) -> anyhow::Result<()> {
    let timeout = probe.probe_timeout.to_string();
    let path = with_query(
        &format!("/proxies/{}/delay", encode(name)),
        &[("url", Some(&probe.url)), ("timeout", Some(&timeout))],
    );
    let client = ctx.client.waiting_at_least(
        Duration::from_millis(probe.probe_timeout.into()) + Duration::from_secs(10),
    );
    let answer = match client.call(Method::GET, &path, None).await {
        Ok(answer) => answer.unwrap_or_default(),
        Err(e) if refused_with(&e) == Some(StatusCode::GATEWAY_TIMEOUT) => {
            bail!("{name}: no answer within {} ms", probe.probe_timeout)
        }
        Err(e) if refused_with(&e) == Some(StatusCode::SERVICE_UNAVAILABLE) => {
            bail!(
                "{name}: the test failed (the proxy could not fetch {})",
                probe.url
            )
        }
        Err(e) => return Err(e),
    };
    if ctx.json {
        return print_json(&answer);
    }
    let delay = answer.get("delay").and_then(Value::as_u64).unwrap_or(0);
    print(&format!("{delay} ms\n"))
}

async fn group(ctx: &Ctx, name: &str) -> anyhow::Result<Value> {
    ctx.client.get(&format!("/group/{}", encode(name))).await
}

/// The group's route after a change: `Proxy -> HK 01`.
async fn show_route(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let answer = group(ctx, name).await?;
    if ctx.json {
        return print_json(&answer);
    }
    let group: ProxyInfo = serde_json::from_value(answer)?;
    print(&format!("{}\n", group.route_text()))
}

/// Route-table proxies and groups, and every proxy-provider member, by name.
async fn all_proxies(ctx: &Ctx) -> anyhow::Result<HashMap<String, ProxyInfo>> {
    let route: ProxyMap = serde_json::from_value(ctx.client.get("/proxies").await?)?;
    let mut proxies = route.proxies;
    for raw in provider_members(ctx).await? {
        let proxy: ProxyInfo = serde_json::from_value(raw)?;
        proxies.entry(proxy.name.clone()).or_insert(proxy);
    }
    Ok(proxies)
}

/// Proxy-provider members, providers by name, members in provider order.
async fn provider_members(ctx: &Ctx) -> anyhow::Result<Vec<Value>> {
    let providers: ProviderMap =
        serde_json::from_value(ctx.client.get("/providers/proxies").await?)?;
    let mut providers: Vec<(String, ProviderMembers)> = providers.providers.into_iter().collect();
    providers.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(providers
        .into_iter()
        .flat_map(|(_, provider)| provider.proxies)
        .collect())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
