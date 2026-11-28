//! Minimal HTTP proxy implementation for AnyTLS client.
//!
//! Supports CONNECT tunneling as well as forwarding HTTP requests
//! via the AnyTLS stream pool.

use crate::client::Client;
use crate::util::{AnyTlsError, Result};
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Start an HTTP proxy server that forwards traffic via AnyTLS.
pub async fn start_http_proxy_server(listen_addr: &str, client: Arc<Client>) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("[HTTP] Listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::debug!("[HTTP] New connection from {}", addr);
                let client_clone = Arc::clone(&client);
                tokio::spawn(async move {
                    if let Err(err) = handle_http_proxy_connection(stream, client_clone).await {
                        tracing::error!("[HTTP] Connection error: {}", err);
                    }
                });
            }
            Err(e) => {
                tracing::error!("[HTTP] Accept error: {}", e);
            }
        }
    }
}

struct ParsedRequest {
    method: String,
    version: String,
    host: String,
    port: u16,
    path: String,
    is_connect: bool,
    headers: Vec<String>,
    body: Vec<u8>,
}

async fn handle_http_proxy_connection(
    mut client_conn: TcpStream,
    client: Arc<Client>,
) -> Result<()> {
    let (header_bytes, remaining) = read_http_header(&mut client_conn).await?;
    let header_str = String::from_utf8(header_bytes.clone())
        .map_err(|e| AnyTlsError::Protocol(format!("Invalid HTTP header encoding: {}", e)))?;

    let request = parse_http_request(&header_str, remaining)?;

    tracing::debug!(
        "[HTTP] Request: method={} host={} port={} path={} connect={}",
        request.method,
        request.host,
        request.port,
        request.path,
        request.is_connect
    );

    let destination = (request.host.clone(), request.port);
    let pooled = match client.create_proxy_stream(destination.clone()).await {
        Ok(res) => res,
        Err(err) => {
            send_http_error(&mut client_conn, 502, "Bad Gateway").await?;
            return Err(err);
        }
    };
    let proxy_stream = Arc::clone(pooled.stream());
    let session = Arc::clone(pooled.session());

    if request.is_connect {
        send_connect_success(&mut client_conn).await?;
    } else {
        let request_bytes = build_forward_request(&request)?;
        session
            .write_data_frame(proxy_stream.id(), Bytes::from(request_bytes))
            .await?;
        if !request.body.is_empty() {
            session
                .write_data_frame(proxy_stream.id(), Bytes::from(request.body.clone()))
                .await?;
        }
    }

    let (mut client_read, mut client_write) = tokio::io::split(client_conn);
    let proxy_stream_read = Arc::clone(&proxy_stream);
    let session_for_write = Arc::clone(&session);
    let stream_id = proxy_stream.id();

    tracing::debug!(
        "[HTTP] Established tunnel for {}:{}, stream={}",
        request.host,
        request.port,
        stream_id
    );

    let to_client = tokio::spawn(async move {
        let reader = proxy_stream_read.reader();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = {
                let mut guard = reader.lock().await;
                match guard.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!("[HTTP] Proxy stream read error: {}", e);
                        break;
                    }
                }
            };
            if client_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });

    let to_proxy = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    tracing::error!("[HTTP] Client read error: {}", e);
                    break;
                }
            };
            if let Err(e) = session_for_write
                .write_data_frame(stream_id, Bytes::from(buf[..n].to_vec()))
                .await
            {
                tracing::error!("[HTTP] Failed to send to proxy stream: {}", e);
                break;
            }
        }
    });

    let _ = tokio::join!(to_client, to_proxy);
    pooled.close().await;

    tracing::debug!(
        "[HTTP] Connection to {}:{} closed (stream {})",
        request.host,
        request.port,
        stream_id
    );
    Ok(())
}

async fn read_http_header(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(AnyTlsError::Protocol(
                "Connection closed before HTTP header complete".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEADER_SIZE {
            return Err(AnyTlsError::Protocol("HTTP header too large".to_string()));
        }
        if let Some(end) = find_header_end(&buf) {
            let header = buf[..end].to_vec();
            let remaining = buf[end..].to_vec();
            return Ok((header, remaining));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_TERMINATOR.len())
        .position(|window| window == HEADER_TERMINATOR)
        .map(|pos| pos + HEADER_TERMINATOR.len())
}

fn parse_http_request(header: &str, body: Vec<u8>) -> Result<ParsedRequest> {
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| AnyTlsError::Protocol("Missing HTTP request line".into()))?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| AnyTlsError::Protocol("Invalid HTTP request line".into()))?;
    let target = parts
        .next()
        .ok_or_else(|| AnyTlsError::Protocol("Invalid HTTP request line".into()))?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    let header_lines: Vec<String> = lines
        .map(|line| line.to_string())
        .filter(|line| !line.is_empty())
        .collect();

    let (host, port, path, is_connect) = determine_target(method, target, &header_lines)?;

    Ok(ParsedRequest {
        method: method.to_string(),
        version: version.to_string(),
        host,
        port,
        path,
        is_connect,
        headers: header_lines,
        body,
    })
}

fn determine_target(
    method: &str,
    target: &str,
    headers: &[String],
) -> Result<(String, u16, String, bool)> {
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443)?;
        return Ok((host, port, String::new(), true));
    }

    let mut host_header: Option<String> = None;
    for header in headers {
        if let Some(rest) = header.strip_prefix("Host:") {
            host_header = Some(rest.trim().to_string());
            break;
        } else if let Some(rest) = header.strip_prefix("host:") {
            host_header = Some(rest.trim().to_string());
            break;
        }
    }

    let mut host = String::new();
    let mut port = 80u16;
    let mut path = target.to_string();

    if target.starts_with("http://") || target.starts_with("https://") {
        let without_scheme = if let Some(pos) = target.find("://") {
            &target[pos + 3..]
        } else {
            target
        };
        if let Some(pos) = without_scheme.find('/') {
            host = without_scheme[..pos].to_string();
            path = without_scheme[pos..].to_string();
        } else {
            host = without_scheme.to_string();
            path = "/".to_string();
        }

        if target.starts_with("https://") {
            port = 443;
        }
    } else if let Some(h) = host_header.clone() {
        host = h;
    }

    if host.is_empty() {
        return Err(AnyTlsError::Protocol(
            "Host header missing for HTTP request".into(),
        ));
    }

    let (host_only, port_resolved) = split_host_port(&host, port)?;
    if !path.starts_with('/') && !path.starts_with('*') {
        path = format!("/{}", path);
    }

    Ok((host_only, port_resolved, path, false))
}

fn split_host_port(value: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(idx) = value.rfind(':') {
        if value[..idx].contains(':') && !value.contains(']') {
            // Probably IPv6 without brackets; require default
            return Ok((value.to_string(), default_port));
        }
        let host_part = &value[..idx];
        let port_part = &value[idx + 1..];
        if let Ok(port) = port_part.parse::<u16>() {
            return Ok((
                host_part
                    .trim()
                    .trim_matches('[')
                    .trim_matches(']')
                    .to_string(),
                port,
            ));
        }
    }
    Ok((
        value.trim().trim_matches('[').trim_matches(']').to_string(),
        default_port,
    ))
}

fn build_forward_request(req: &ParsedRequest) -> Result<Vec<u8>> {
    let mut new_request = Vec::new();
    let request_line = format!(
        "{} {} {}\r\n",
        req.method,
        if req.path.is_empty() { "/" } else { &req.path },
        req.version
    );
    new_request.extend_from_slice(request_line.as_bytes());

    let host_header_value = if req.port == 80 || req.port == 443 {
        req.host.clone()
    } else {
        format!("{}:{}", req.host, req.port)
    };

    let mut host_written = false;
    for header in &req.headers {
        if header.is_empty() {
            continue;
        }
        if header.to_ascii_lowercase().starts_with("host:") {
            host_written = true;
            new_request.extend_from_slice(format!("Host: {}\r\n", host_header_value).as_bytes());
        } else {
            new_request.extend_from_slice(header.as_bytes());
            new_request.extend_from_slice(b"\r\n");
        }
    }
    if !host_written {
        new_request.extend_from_slice(format!("Host: {}\r\n", host_header_value).as_bytes());
    }
    new_request.extend_from_slice(b"\r\n");
    Ok(new_request)
}

async fn send_connect_success(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(AnyTlsError::Io)
}

async fn send_http_error(stream: &mut TcpStream, code: u16, message: &str) -> Result<()> {
    let body = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        code, message
    );
    stream
        .write_all(body.as_bytes())
        .await
        .map_err(AnyTlsError::Io)
}
