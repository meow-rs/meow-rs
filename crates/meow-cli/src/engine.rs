//! The engine's settings: status, mode, log level, TUN, rules, listeners
//! and config reloads.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use hyper::Method;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::format::{self, Table};
use crate::{print, print_json, Ctx, LogLevel, Mode, Switch};

/// A reload re-fetches providers that have no cache yet.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
struct Version {
    version: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Configs {
    mode: String,
    #[serde(rename = "log-level")]
    log_level: String,
    #[serde(rename = "mixed-port")]
    mixed_port: Option<u16>,
    #[serde(rename = "socks-port")]
    socks_port: Option<u16>,
    port: Option<u16>,
    #[serde(rename = "tproxy-port")]
    tproxy_port: u16,
    #[serde(rename = "allow-lan")]
    allow_lan: bool,
    #[serde(rename = "tun-enable")]
    tun_enable: bool,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ConnectionTotals {
    upload_total: u64,
    download_total: u64,
    connections: Vec<IgnoredAny>,
}

#[derive(Deserialize)]
struct RuleInfo {
    index: usize,
    #[serde(rename = "type")]
    rule_type: String,
    payload: String,
    proxy: String,
}

#[derive(Deserialize)]
struct Listener {
    name: String,
    #[serde(rename = "type")]
    listener_type: String,
    listen: String,
    port: u16,
}

pub async fn status(ctx: &Ctx) -> anyhow::Result<()> {
    let version = ctx.client.get("/version").await?;
    let configs = ctx.client.get("/configs").await?;
    let connections = ctx.client.get("/connections").await?;
    let totals: ConnectionTotals = serde_json::from_value(connections)?;
    if ctx.json {
        return print_json(&json!({
            "controller": ctx.client.authority(),
            "version": version,
            "configs": configs,
            "connections": totals.connections.len(),
            "uploadTotal": totals.upload_total,
            "downloadTotal": totals.download_total,
        }));
    }
    let version: Version = serde_json::from_value(version)?;
    let configs: Configs = serde_json::from_value(configs)?;
    let ports: Vec<String> = [
        ("mixed", configs.mixed_port),
        ("socks", configs.socks_port),
        ("http", configs.port),
        ("tproxy", Some(configs.tproxy_port)),
    ]
    .into_iter()
    .filter_map(|(name, port)| {
        port.filter(|&port| port > 0)
            .map(|port| format!("{name} {port}"))
    })
    .collect();
    let mut text = String::new();
    writeln!(
        text,
        "meow {} at {}",
        version.version,
        ctx.client.authority()
    )?;
    writeln!(text, "mode         {}", configs.mode)?;
    writeln!(text, "log level    {}", configs.log_level)?;
    writeln!(text, "tun          {}", on_off(configs.tun_enable))?;
    if !ports.is_empty() {
        writeln!(text, "ports        {}", ports.join(", "))?;
    }
    writeln!(text, "allow lan    {}", on_off(configs.allow_lan))?;
    writeln!(
        text,
        "connections  {} open, {} up, {} down since start",
        totals.connections.len(),
        format::bytes(totals.upload_total),
        format::bytes(totals.download_total)
    )?;
    print(&text)
}

pub async fn mode(ctx: &Ctx, mode: Option<Mode>) -> anyhow::Result<()> {
    if let Some(mode) = mode {
        patch(ctx, json!({ "mode": mode.as_str() })).await?;
    }
    let configs = configs(ctx).await?;
    setting(ctx, "mode", &configs.mode)
}

pub async fn log_level(ctx: &Ctx, level: Option<LogLevel>) -> anyhow::Result<()> {
    if let Some(level) = level {
        patch(ctx, json!({ "log-level": level.as_str() })).await?;
    }
    let configs = configs(ctx).await?;
    setting(ctx, "log-level", &configs.log_level)
}

pub async fn tun(ctx: &Ctx, state: Option<Switch>) -> anyhow::Result<()> {
    if let Some(state) = state {
        let enable = matches!(state, Switch::On);
        patch(ctx, json!({ "tun": { "enable": enable } })).await?;
    }
    let configs = configs(ctx).await?;
    if ctx.json {
        return print_json(&json!({ "tun-enable": configs.tun_enable }));
    }
    print(&format!("{}\n", on_off(configs.tun_enable)))
}

pub async fn rules(ctx: &Ctx, filter: Option<&str>) -> anyhow::Result<()> {
    let mut answer = ctx.client.get("/rules").await?;
    let rules = answer
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .context("meow answered /rules without a rule list")?;
    let mut shown = Vec::new();
    for raw in rules.drain(..) {
        let rule: RuleInfo = serde_json::from_value(raw.clone())?;
        if format::matches(filter, &[&rule.rule_type, &rule.payload, &rule.proxy]) {
            shown.push((raw, rule));
        }
    }
    if ctx.json {
        let rules: Vec<Value> = shown.into_iter().map(|(raw, _)| raw).collect();
        return print_json(&json!({ "rules": rules }));
    }
    let mut table = Table::new(&["INDEX", "TYPE", "PAYLOAD", "TARGET"]);
    for (_, rule) in shown {
        table.row(vec![
            rule.index.to_string(),
            rule.rule_type,
            rule.payload,
            rule.proxy,
        ]);
    }
    print(&table.render())
}

pub async fn listeners(ctx: &Ctx) -> anyhow::Result<()> {
    let answer = ctx.client.get("/listeners").await?;
    ctx.show(answer, |listeners: Vec<Listener>| {
        if listeners.is_empty() {
            return Ok("no named listeners (top-level ports show in `meow-cli status`)\n".into());
        }
        let mut table = Table::new(&["TYPE", "ADDRESS", "NAME"]);
        for listener in listeners {
            let host = if listener.listen.contains(':') {
                format!("[{}]", listener.listen)
            } else {
                listener.listen
            };
            table.row(vec![
                listener.listener_type,
                format!("{host}:{}", listener.port),
                listener.name,
            ]);
        }
        Ok(table.render())
    })
}

/// Sends the file's text, so the daemon need not be able to read the path
/// (another host, another user); relative paths inside the config resolve
/// against the daemon's home as on any reload.
pub async fn reload(ctx: &Ctx, path: &Path, force: bool) -> anyhow::Result<()> {
    let text = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let payload = base64::engine::general_purpose::STANDARD.encode(text);
    let url = if force {
        "/configs?force=true"
    } else {
        "/configs"
    };
    ctx.client
        .waiting_at_least(RELOAD_TIMEOUT)
        .call(Method::PUT, url, Some(&json!({ "payload": payload })))
        .await?;
    ctx.done(&format!("reloaded {}", path.display()))
}

async fn patch(ctx: &Ctx, body: Value) -> anyhow::Result<()> {
    ctx.client
        .call(Method::PATCH, "/configs", Some(&body))
        .await?;
    Ok(())
}

async fn configs(ctx: &Ctx) -> anyhow::Result<Configs> {
    Ok(serde_json::from_value(ctx.client.get("/configs").await?)?)
}

fn setting(ctx: &Ctx, key: &str, value: &str) -> anyhow::Result<()> {
    if ctx.json {
        return print_json(&json!({ key: value }));
    }
    print(&format!("{value}\n"))
}

fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}
