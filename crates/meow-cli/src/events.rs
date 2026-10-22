//! What meow did and carried: the logbook, the live log, traffic rates and
//! per-proxy totals.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::num::NonZeroUsize;

use hyper::Method;
use serde::Deserialize;

use crate::client::with_query;
use crate::format::{self, Table};
use crate::{print, Ctx, LogLevel, LogbookQuery};

#[derive(Deserialize, Default)]
#[serde(default)]
struct LogbookPage {
    enabled: bool,
    entries: Vec<LogbookEntry>,
    more: bool,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LogbookEntry {
    id: u64,
    time: String,
    last: Option<String>,
    count: u32,
    kind: String,
    level: String,
    subject: String,
    message: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LogLine {
    #[serde(rename = "type")]
    level: String,
    payload: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Traffic {
    up: u64,
    down: u64,
    up_total: u64,
    down_total: u64,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Statistics {
    upload_total: u64,
    download_total: u64,
    proxies: BTreeMap<String, ProxyTotals>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ProxyTotals {
    upload: u64,
    download: u64,
}

pub async fn logbook(ctx: &Ctx, query: &LogbookQuery) -> anyhow::Result<()> {
    let limit = query.limit.to_string();
    let before = query.before.map(|id| id.to_string());
    let path = with_query(
        "/logbook",
        &[
            ("limit", Some(&limit)),
            ("level", query.level.map(crate::EventLevel::as_str)),
            ("kind", query.kind.as_deref()),
            ("subject", query.subject.as_deref()),
            ("before", before.as_deref()),
        ],
    );
    let answer = ctx.client.get(&path).await?;
    ctx.show(answer, |page: LogbookPage| {
        if !page.enabled {
            return Ok(
                "the logbook is off: `logbook: {enable: false}`, or a build without it\n".into(),
            );
        }
        if page.entries.is_empty() {
            return Ok("no entries\n".into());
        }
        let oldest = page.entries.last().map_or(0, |entry| entry.id);
        let mut table = Table::new(&["ID", "TIME", "LEVEL", "KIND", "EVENT"]);
        for entry in page.entries {
            table.row(vec![
                entry.id.to_string(),
                format::time(&entry.time),
                entry.level.clone(),
                entry.kind.clone(),
                event_text(&entry),
            ]);
        }
        let mut text = table.render();
        if page.more {
            writeln!(text, "older entries: {}", older_page(query, oldest))?;
        }
        Ok(text)
    })
}

/// The command for the entries before `oldest`, with the same filters.
fn older_page(query: &LogbookQuery, oldest: u64) -> String {
    let mut command = format!("meow-cli logbook --before {oldest}");
    if query.limit != crate::LOGBOOK_LIMIT {
        let _ = write!(command, " --limit {}", query.limit);
    }
    if let Some(level) = query.level {
        let _ = write!(command, " --level {}", level.as_str());
    }
    for (flag, value) in [("--kind", &query.kind), ("--subject", &query.subject)] {
        if let Some(value) = value {
            let _ = write!(command, " {flag} {}", shell_word(value));
        }
    }
    command
}

/// `word` as a POSIX shell reads it back.
fn shell_word(word: &str) -> String {
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"-._/:@".contains(&byte);
    if !word.is_empty() && word.bytes().all(plain) {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

pub async fn logbook_clear(ctx: &Ctx) -> anyhow::Result<()> {
    ctx.client.call(Method::DELETE, "/logbook", None).await?;
    ctx.done("cleared the logbook")
}

pub async fn log(ctx: &Ctx, level: LogLevel, count: Option<NonZeroUsize>) -> anyhow::Result<()> {
    let path = with_query("/logs", &[("level", Some(level.as_str()))]);
    let json = ctx.json;
    let mut left = count.map(NonZeroUsize::get);
    ctx.client
        .stream(&path, |line| {
            if json {
                print(&format!("{line}\n"))?;
            } else {
                let entry: LogLine = serde_json::from_str(line)?;
                print(&format!("{:<7}  {}\n", entry.level, entry.payload))?;
            }
            Ok(count_down(&mut left))
        })
        .await
}

pub async fn traffic(ctx: &Ctx, count: Option<NonZeroUsize>) -> anyhow::Result<()> {
    let json = ctx.json;
    let mut left = count.map(NonZeroUsize::get);
    ctx.client
        .stream("/traffic", |line| {
            if json {
                print(&format!("{line}\n"))?;
            } else {
                let sample: Traffic = serde_json::from_str(line)?;
                print(&format!(
                    "up {:>10}/s  down {:>10}/s  total up {}, down {}\n",
                    format::bytes(sample.up),
                    format::bytes(sample.down),
                    format::bytes(sample.up_total),
                    format::bytes(sample.down_total)
                ))?;
            }
            Ok(count_down(&mut left))
        })
        .await
}

pub async fn stats(ctx: &Ctx) -> anyhow::Result<()> {
    let answer = ctx.client.get("/statistics").await?;
    ctx.show(answer, |stats: Statistics| {
        let mut text = format!(
            "{} up, {} down since start\n",
            format::bytes(stats.upload_total),
            format::bytes(stats.download_total)
        );
        let mut proxies: Vec<(String, ProxyTotals)> = stats.proxies.into_iter().collect();
        // The busiest first.
        proxies.sort_by_key(|(_, totals)| std::cmp::Reverse(totals.upload + totals.download));
        let mut table = Table::new(&["UP", "DOWN", "PROXY"]);
        for (name, totals) in proxies {
            table.row(vec![
                format::bytes(totals.upload),
                format::bytes(totals.download),
                name,
            ]);
        }
        if !table.is_empty() {
            text.push_str(&table.render());
        }
        Ok(text)
    })
}

/// `[subject] message (x3, last 08:31:00Z)`; `--json` has the fields.
fn event_text(entry: &LogbookEntry) -> String {
    let mut text = String::new();
    if !entry.subject.is_empty() {
        text.push('[');
        text.push_str(&entry.subject);
        text.push_str("] ");
    }
    text.push_str(&entry.message);
    if entry.count > 1 {
        let last = entry.last.as_deref().map(format::time).unwrap_or_default();
        text = format!("{text} (x{}, last {last})", entry.count);
    }
    text
}

/// Counts one line off `--count`; `false` once it is used up.
fn count_down(left: &mut Option<usize>) -> bool {
    match left {
        Some(left) => {
            *left = left.saturating_sub(1);
            *left > 0
        }
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_older_page_keeps_the_filters() {
        let query = LogbookQuery {
            limit: 20,
            level: Some(crate::EventLevel::Warning),
            kind: Some("config".into()),
            subject: Some("节点 it's".into()),
            before: Some(900),
        };
        assert_eq!(
            older_page(&query, 812),
            "meow-cli logbook --before 812 --limit 20 --level warning --kind config \
             --subject '节点 it'\\''s'"
        );
        let query = LogbookQuery {
            limit: crate::LOGBOOK_LIMIT,
            level: None,
            kind: None,
            subject: None,
            before: None,
        };
        assert_eq!(older_page(&query, 7), "meow-cli logbook --before 7");
    }
}
