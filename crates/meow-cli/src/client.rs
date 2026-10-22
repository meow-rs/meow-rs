//! A small HTTP/1.1 client for the controller: one connection per request,
//! Bearer auth, JSON bodies, and the NDJSON streams `/logs` and `/traffic`
//! serve to a client that does not upgrade to a WebSocket.

use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpStream;

use crate::controller::Endpoint;

#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
    timeout: Duration,
}

impl Client {
    pub fn new(endpoint: Endpoint, timeout: Duration) -> Self {
        Self { endpoint, timeout }
    }

    /// `host:port` of the controller.
    pub fn authority(&self) -> &str {
        &self.endpoint.authority
    }

    /// The same client, waiting at least `timeout` for an answer: a delay
    /// test may take longer than the default.
    pub fn waiting_at_least(&self, timeout: Duration) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            timeout: self.timeout.max(timeout),
        }
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.call(Method::GET, path, None)
            .await?
            .ok_or_else(|| anyhow!("GET {path} answered with no body"))
    }

    /// One request; `None` for an empty answer (`204 No Content`).
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> anyhow::Result<Option<Value>> {
        let exchange = async {
            let response = self.send(method, path, body).await?;
            let status = response.status();
            let bytes = response
                .into_body()
                .collect()
                .await
                .context("reading the answer")?
                .to_bytes();
            if !status.is_success() {
                return Err(api_error(status, &bytes));
            }
            if bytes.iter().all(u8::is_ascii_whitespace) {
                return Ok(None);
            }
            serde_json::from_slice(&bytes)
                .map(Some)
                .with_context(|| format!("{path} answered with something other than JSON"))
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| self.timed_out())?
    }

    /// Follows an NDJSON stream, handing each line to `on_line` until it
    /// returns `false`. Only the response head is bounded by the timeout.
    pub async fn stream(
        &self,
        path: &str,
        mut on_line: impl FnMut(&str) -> anyhow::Result<bool>,
    ) -> anyhow::Result<()> {
        let response = tokio::time::timeout(self.timeout, self.send(Method::GET, path, None))
            .await
            .map_err(|_| self.timed_out())??;
        let status = response.status();
        let mut body = response.into_body();
        if !status.is_success() {
            let bytes = body
                .collect()
                .await
                .context("reading the answer")?
                .to_bytes();
            return Err(api_error(status, &bytes));
        }
        let mut pending = Vec::new();
        while let Some(frame) = body.frame().await {
            let Ok(data) = frame.context("reading the stream")?.into_data() else {
                continue;
            };
            pending.extend_from_slice(&data);
            while let Some(end) = pending.iter().position(|&byte| byte == b'\n') {
                let line: Vec<u8> = pending.drain(..=end).collect();
                let line = String::from_utf8_lossy(&line);
                let line = line.trim();
                if !line.is_empty() && !on_line(line)? {
                    return Ok(());
                }
            }
        }
        bail!("meow closed the stream")
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> anyhow::Result<Response<Incoming>> {
        let authority = self.authority();
        let stream = TcpStream::connect(authority).await.with_context(|| {
            format!(
                "cannot reach meow's controller at {authority}: is meow running, with \
                 external-controller set to this address?"
            )
        })?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .context("HTTP handshake with the controller")?;
        // Drives the connection until the answer is read; dropping `sender`
        // closes it after that.
        tokio::spawn(connection);

        let mut request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(HOST, authority);
        if let Some(secret) = &self.endpoint.secret {
            request = request.header(AUTHORIZATION, format!("Bearer {secret}"));
        }
        let body = match body {
            Some(value) => {
                request = request.header(CONTENT_TYPE, "application/json");
                Full::new(Bytes::from(serde_json::to_vec(value)?))
            }
            None => Full::new(Bytes::new()),
        };
        // The error names the method and path only: never the secret.
        let request = request
            .body(body)
            .map_err(|_| anyhow!("cannot build {method} {path}: check the secret's characters"))?;
        sender
            .send_request(request)
            .await
            .with_context(|| format!("{method} {path}"))
    }

    fn timed_out(&self) -> anyhow::Error {
        anyhow!(
            "no answer from {} within {} s",
            self.authority(),
            self.timeout.as_secs()
        )
    }
}

/// A request meow answered with an error status.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    /// Its JSON `message`, else the body's text.
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.status == StatusCode::UNAUTHORIZED {
            return f.write_str(
                "meow wants the API secret (401): set MEOW_SECRET, pass --secret-stdin, or \
                 point --config at its config; a meow running as another user, root \
                 included, publishes it for that user only",
            );
        }
        if self.message.is_empty() {
            write!(f, "meow answered {}", self.status)
        } else {
            write!(f, "meow answered {}: {}", self.status, self.message)
        }
    }
}

impl std::error::Error for ApiError {}

fn api_error(status: StatusCode, body: &[u8]) -> anyhow::Error {
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("message")?.as_str().map(str::to_string))
        .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string());
    ApiError { status, message }.into()
}

/// The status of a request meow refused, if `error` is one.
pub fn refused_with(error: &anyhow::Error) -> Option<StatusCode> {
    error.downcast_ref::<ApiError>().map(|e| e.status)
}

/// Percent-encodes a path segment or query value: proxy and group names
/// carry spaces, `/`, `#`, CJK and emoji.
pub fn encode(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
    }
    encoded
}

/// `path?key=value&…` with the set values encoded.
pub fn with_query(path: &str, pairs: &[(&str, Option<&str>)]) -> String {
    let mut url = path.to_string();
    let mut separator = '?';
    for (key, value) in pairs {
        if let Some(value) = value {
            url.push(separator);
            url.push_str(key);
            url.push('=');
            url.push_str(&encode(value));
            separator = '&';
        }
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_encoded_whole() {
        assert_eq!(
            encode("节点 Proxy/HK#1"),
            "%E8%8A%82%E7%82%B9%20Proxy%2FHK%231"
        );
        assert_eq!(encode("Auto-1_a.b~"), "Auto-1_a.b~");
        assert_eq!(
            with_query(
                "/logs",
                &[("level", Some("info")), ("x", None), ("q", Some("a b"))]
            ),
            "/logs?level=info&q=a%20b"
        );
    }
}
