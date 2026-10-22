//! Lookups through meow's resolver, its answer cache, and the flushes.

use std::fmt::Write as _;

use hyper::Method;
use serde::Deserialize;

use crate::client::with_query;
use crate::format::Table;
use crate::Ctx;

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct Answer {
    status: u16,
    answer: Vec<Record>,
    authority: Vec<Record>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Record {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CacheEntry {
    name: String,
    ips: Vec<String>,
    from_server: Option<String>,
    ttl: u64,
}

pub async fn query(ctx: &Ctx, name: &str, qtype: &str) -> anyhow::Result<()> {
    let path = with_query("/dns/query", &[("name", Some(name)), ("type", Some(qtype))]);
    let answer = ctx.client.get(&path).await?;
    ctx.show(answer, |answer: Answer| {
        if answer.answer.is_empty() {
            let mut text = String::new();
            let status = rcode(answer.status);
            writeln!(
                text,
                "no {} record for {name} ({status})",
                qtype.to_uppercase()
            )?;
            for record in &answer.authority {
                let kind = record_type(record.record_type);
                writeln!(text, "authority  {kind} {} {}", record.name, record.data)?;
            }
            return Ok(text);
        }
        let mut table = Table::new(&["TYPE", "TTL", "NAME", "DATA"]);
        for record in answer.answer {
            table.row(vec![
                record_type(record.record_type),
                record.ttl.to_string(),
                record.name,
                record.data,
            ]);
        }
        Ok(table.render())
    })
}

pub async fn cache(ctx: &Ctx, search: Option<&str>, limit: usize) -> anyhow::Result<()> {
    let limit = limit.to_string();
    let path = with_query(
        "/dns/results",
        &[("search", search), ("limit", Some(&limit))],
    );
    let answer = ctx.client.get(&path).await?;
    ctx.show(answer, |entries: Vec<CacheEntry>| {
        if entries.is_empty() {
            return Ok("no cached answers\n".into());
        }
        let mut table = Table::new(&["TTL", "NAME", "ANSWERS"]);
        for entry in entries {
            let mut answers = entry.ips.join(", ");
            if let Some(server) = entry.from_server {
                answers.push_str("  (from ");
                answers.push_str(&server);
                answers.push(')');
            }
            table.row(vec![entry.ttl.to_string(), entry.name, answers]);
        }
        Ok(table.render())
    })
}

pub async fn flush(ctx: &Ctx, fake_ip: bool) -> anyhow::Result<()> {
    let (path, done) = if fake_ip {
        ("/cache/fakeip/flush", "dropped every fake-IP mapping")
    } else {
        ("/cache/dns/flush", "emptied the DNS cache")
    };
    ctx.client.call(Method::POST, path, None).await?;
    ctx.done(done)
}

/// The record type's name, else its number.
fn record_type(code: u16) -> String {
    let name = match code {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        257 => "CAA",
        _ => return code.to_string(),
    };
    name.to_string()
}

fn rcode(status: u16) -> String {
    let name = match status {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => return format!("rcode {status}"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_read_as_names() {
        assert_eq!(record_type(28), "AAAA");
        assert_eq!(record_type(99), "99");
        assert_eq!(rcode(3), "NXDOMAIN");
    }
}
