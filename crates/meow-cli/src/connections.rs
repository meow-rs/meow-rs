//! Active connections: list, details with notes, close.

use std::fmt::Write as _;

use anyhow::bail;
use hyper::Method;
use serde::Deserialize;
use serde_json::Value;

use crate::client::encode;
use crate::format::{self, Table};
use crate::{print, print_json, Ctx};

/// Length of a full connection id (a hyphenated UUID).
const FULL_ID: usize = 36;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Connections {
    connections: Vec<Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Connection {
    id: String,
    metadata: Metadata,
    upload: u64,
    download: u64,
    start: String,
    /// The leaf that dials first, the rule's target last.
    chains: Vec<String>,
    rule: String,
    #[serde(rename = "rulePayload")]
    rule_payload: String,
    closed: bool,
    end: Option<String>,
    notes: Vec<Note>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Metadata {
    network: String,
    #[serde(rename = "type")]
    conn_type: String,
    #[serde(rename = "sourceIP")]
    source_ip: Option<String>,
    #[serde(rename = "sourcePort")]
    source_port: Value,
    #[serde(rename = "destinationIP")]
    destination_ip: Option<String>,
    #[serde(rename = "destinationPort")]
    destination_port: Value,
    host: String,
    #[serde(rename = "sniffHost")]
    sniff_host: String,
    process: String,
    #[serde(rename = "processPath")]
    process_path: String,
    #[serde(rename = "inboundName")]
    inbound_name: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Note {
    time: String,
    kind: String,
    text: String,
}

impl Connection {
    /// `example.com:443`, or the address when the flow has no host name.
    fn destination(&self) -> String {
        let meta = &self.metadata;
        let host = [&meta.host, &meta.sniff_host]
            .into_iter()
            .find(|host| !host.is_empty())
            .cloned()
            .or_else(|| meta.destination_ip.clone())
            .unwrap_or_default();
        address(&host, &meta.destination_port)
    }

    /// `Proxy > Auto > HK 01`: the rule's target first.
    fn route(&self) -> String {
        let hops: Vec<&str> = self.chains.iter().rev().map(String::as_str).collect();
        hops.join(" > ")
    }

    fn rule_text(&self) -> String {
        if self.rule_payload.is_empty() {
            self.rule.clone()
        } else {
            format!("{},{}", self.rule, self.rule_payload)
        }
    }

    fn short_id(&self) -> &str {
        self.id.get(..8).unwrap_or(&self.id)
    }
}

pub async fn list(ctx: &Ctx, filter: Option<&str>) -> anyhow::Result<()> {
    let mut entries = open_connections(ctx).await?;
    entries.retain(|(_, conn)| {
        let meta = &conn.metadata;
        let mut fields = vec![
            conn.id.as_str(),
            meta.host.as_str(),
            meta.sniff_host.as_str(),
            meta.process.as_str(),
            conn.rule.as_str(),
            conn.rule_payload.as_str(),
        ];
        fields.extend(meta.destination_ip.as_deref());
        fields.extend(conn.chains.iter().map(String::as_str));
        format::matches(filter, &fields)
    });
    if ctx.json {
        let list: Vec<Value> = entries.into_iter().map(|(raw, _)| raw).collect();
        return print_json(&Value::Array(list));
    }
    if entries.is_empty() {
        return print("no open connections\n");
    }
    let mut table = Table::new(&["ID", "NET", "UP", "DOWN", "RULE", "DESTINATION -> ROUTE"]);
    for (_, conn) in &entries {
        table.row(vec![
            conn.short_id().to_string(),
            conn.metadata.network.clone(),
            format::bytes(conn.upload),
            format::bytes(conn.download),
            conn.rule_text(),
            format!("{} -> {}", conn.destination(), conn.route()),
        ]);
    }
    print(&table.render())
}

pub async fn show(ctx: &Ctx, id: &str) -> anyhow::Result<()> {
    let id = resolve_id(ctx, id).await?;
    let answer = ctx
        .client
        .get(&format!("/connections/{}", encode(&id)))
        .await?;
    ctx.show(answer, |conn: Connection| {
        let meta = &conn.metadata;
        let mut text = String::new();
        writeln!(text, "{}", conn.id)?;
        writeln!(text, "destination  {}", conn.destination())?;
        if let Some(ip) = &meta.destination_ip {
            writeln!(text, "address      {}", address(ip, &meta.destination_port))?;
        }
        if let Some(ip) = &meta.source_ip {
            writeln!(text, "source       {}", address(ip, &meta.source_port))?;
        }
        writeln!(text, "network      {} via {}", meta.network, meta.conn_type)?;
        if !meta.inbound_name.is_empty() {
            writeln!(text, "inbound      {}", meta.inbound_name)?;
        }
        if !meta.process.is_empty() {
            let path = if meta.process_path.is_empty() {
                String::new()
            } else {
                format!(" ({})", meta.process_path)
            };
            writeln!(text, "process      {}{path}", meta.process)?;
        }
        writeln!(text, "rule         {}", conn.rule_text())?;
        writeln!(text, "route        {}", conn.route())?;
        writeln!(
            text,
            "traffic      {} up, {} down",
            format::bytes(conn.upload),
            format::bytes(conn.download)
        )?;
        writeln!(text, "started      {}", format::time(&conn.start))?;
        if conn.closed {
            let end = conn.end.as_deref().map(format::time).unwrap_or_default();
            writeln!(text, "closed       {end}")?;
        }
        for note in &conn.notes {
            writeln!(
                text,
                "  {}  {:<10}  {}",
                format::time(&note.time),
                note.kind,
                note.text
            )?;
        }
        Ok(text)
    })
}

pub async fn close(ctx: &Ctx, ids: &[String], all: bool) -> anyhow::Result<()> {
    if all {
        ctx.client
            .call(Method::DELETE, "/connections", None)
            .await?;
        return ctx.done("closed every connection");
    }
    for id in ids {
        // meow answers 204 for any well-formed id, so look it up first.
        let id = open_id(ctx, id).await?;
        ctx.client
            .call(
                Method::DELETE,
                &format!("/connections/{}", encode(&id)),
                None,
            )
            .await?;
        ctx.done(&format!("closed {id}"))?;
    }
    Ok(())
}

/// A full id as given, as meow still shows a connection that closed a
/// moment ago; a prefix matched against the open connections.
async fn resolve_id(ctx: &Ctx, id: &str) -> anyhow::Result<String> {
    if id.len() == FULL_ID {
        return Ok(id.to_string());
    }
    open_id(ctx, id).await
}

/// The open connection whose id is `id` or starts with it.
async fn open_id(ctx: &Ctx, id: &str) -> anyhow::Result<String> {
    if id.is_empty() {
        bail!("give a connection id, or the start of one");
    }
    let open = open_connections(ctx).await?;
    let mut matching = open
        .iter()
        .map(|(_, conn)| &conn.id)
        .filter(|full| full.starts_with(id));
    match (matching.next(), matching.next()) {
        (Some(full), None) => Ok(full.clone()),
        (None, _) => bail!("no open connection's id starts with {id}"),
        (Some(_), Some(_)) => bail!("more than one open connection's id starts with {id}"),
    }
}

/// Open connections, oldest first, each with what meow wrote for it.
async fn open_connections(ctx: &Ctx) -> anyhow::Result<Vec<(Value, Connection)>> {
    let answer: Connections = serde_json::from_value(ctx.client.get("/connections").await?)?;
    let mut entries = Vec::with_capacity(answer.connections.len());
    for raw in answer.connections {
        let conn: Connection = serde_json::from_value(raw.clone())?;
        entries.push((raw, conn));
    }
    entries.sort_by(|a, b| a.1.start.cmp(&b.1.start));
    Ok(entries)
}

/// `host:port`, bracketing an IPv6 address.
fn address(host: &str, port: &Value) -> String {
    let port = match port {
        Value::String(port) => port.clone(),
        Value::Number(port) => port.to_string(),
        _ => String::new(),
    };
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
