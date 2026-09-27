//! HTTP/1.1 Upgrade transport layer (`httpupgrade` feature).
//!
//! Performs an HTTP/1.1 `Upgrade: websocket` handshake over the inner stream,
//! validates the `101 Switching Protocols` response (including the presence of
//! the `Upgrade` header), and returns the stream for raw byte exchange.
//!
//! A non-101 response (including `200 OK`) is rejected with
//! [`TransportError::HttpUpgrade`] containing the received status code.
//!
//! upstream: transport/vmess/httpupgrade.go

use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

use crate::{Result, Stream, Transport, TransportError};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the HTTP/1.1 Upgrade transport layer.
///
/// upstream: `http-upgrade-opts` YAML key block.
#[derive(Debug, Clone)]
pub struct HttpUpgradeConfig {
    /// The request path (e.g. `"/upgrade"`).
    ///
    /// upstream: `http-upgrade-opts.path`; default `"/"`.
    pub path: String,

    /// Overrides the `Host` header.  If `None`, the layer uses `"localhost"`.
    ///
    /// upstream: `http-upgrade-opts.host`.
    pub host_header: Option<String>,

    /// Additional HTTP headers sent with the upgrade request.
    ///
    /// upstream: `http-upgrade-opts.headers`.
    pub extra_headers: Vec<(String, String)>,
}

impl Default for HttpUpgradeConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            host_header: None,
            extra_headers: Vec::new(),
        }
    }
}

// ─── HttpUpgradeLayer ────────────────────────────────────────────────────────

/// Transport layer that performs an HTTP/1.1 Upgrade handshake before
/// returning the raw byte stream.
pub struct HttpUpgradeLayer {
    config: HttpUpgradeConfig,
}

impl HttpUpgradeLayer {
    /// Create an `HttpUpgradeLayer` from the given configuration.
    pub fn new(config: HttpUpgradeConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for HttpUpgradeLayer {
    async fn connect(&self, mut inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        validate_request_config(&self.config)?;

        let host = self.config.host_header.as_deref().unwrap_or("localhost");

        // ── Build the HTTP/1.1 upgrade request ───────────────────────────────
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
            self.config.path, host
        );
        for (k, v) in &self.config.extra_headers {
            request.push_str(k);
            request.push_str(": ");
            request.push_str(v);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");

        inner
            .write_all(request.as_bytes())
            .await
            .map_err(TransportError::Io)?;

        // ── Read the HTTP/1.1 response headers in chunks ─────────────────────
        //
        // Read into a small stack buffer and scan for the CRLF-CRLF separator
        // (a typical ~300-byte response previously cost ~300 one-byte reads).
        // Any bytes received past the separator belong to the stream payload
        // and are retained as initial buffered data on the returned stream.
        let mut header_buf: Vec<u8> = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        let header_end = loop {
            let n = inner.read(&mut chunk).await.map_err(TransportError::Io)?;
            if n == 0 {
                return Err(TransportError::HttpUpgrade(
                    "connection closed before receiving HTTP response".into(),
                ));
            }
            // The separator may straddle the chunk boundary: rescan from up
            // to 3 bytes before the previously buffered end.
            let scan_from = header_buf.len().saturating_sub(3);
            header_buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = header_buf[scan_from..]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
            {
                break scan_from + pos + 4;
            }
            if header_buf.len() > 8192 {
                return Err(TransportError::HttpUpgrade(
                    "HTTP response headers exceeded 8192 bytes".into(),
                ));
            }
        };

        // ── Parse with httparse ───────────────────────────────────────────────
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&header_buf[..header_end]) {
            Ok(httparse::Status::Complete(_)) => {}
            Ok(httparse::Status::Partial) => {
                // Should not happen: we read until \r\n\r\n above.
                return Err(TransportError::HttpUpgrade(
                    "incomplete HTTP response headers (internal error)".into(),
                ));
            }
            Err(e) => {
                return Err(TransportError::HttpUpgrade(format!(
                    "HTTP response parse error: {e}"
                )));
            }
        }

        let status = response.code.unwrap_or(0);

        // ── Require 101 Switching Protocols ──────────────────────────────────
        //
        // upstream: server returning 200 is also rejected — not a divergence,
        // HTTP upgrade semantics require 101.
        if status != 101 {
            return Err(TransportError::HttpUpgrade(format!(
                "server returned {status}, expected 101 Switching Protocols"
            )));
        }

        // ── Require the Upgrade response header ──────────────────────────────
        let has_upgrade = response
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("Upgrade"));
        if !has_upgrade {
            return Err(TransportError::HttpUpgrade(
                "server returned 101 without Upgrade header".into(),
            ));
        }

        // Connection is now a raw byte stream. Bytes read past the header
        // terminator are stream payload — hand them back first.
        if header_end < header_buf.len() {
            header_buf.drain(..header_end);
            Ok(Box::new(PrefixedStream {
                prefix: header_buf,
                off: 0,
                inner,
            }))
        } else {
            Ok(inner)
        }
    }
}

/// Bound on remote-supplied `http-upgrade-opts.headers` — shared with xhttp
/// (issue #648). Enforced by `connect()` via `validate_request_config`.
pub use crate::MAX_EXTRA_HEADERS;

fn validate_request_config(config: &HttpUpgradeConfig) -> Result<()> {
    validate_path(&config.path)?;
    if let Some(host) = &config.host_header {
        validate_host_header(host)?;
    }
    // Structural bound before the per-entry scan — an oversized list bails
    // without paying the O(n) byte checks first.
    if config.extra_headers.len() > MAX_EXTRA_HEADERS {
        return Err(TransportError::Config(format!(
            "httpupgrade: too many extra headers ({}, max {MAX_EXTRA_HEADERS})",
            config.extra_headers.len()
        )));
    }
    for (name, value) in &config.extra_headers {
        validate_header_name(name)?;
        validate_header_value(name, value)?;
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(TransportError::Config(
            "httpupgrade: path must start with '/'".into(),
        ));
    }
    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(TransportError::Config(
            "httpupgrade: path contains whitespace or control bytes".into(),
        ));
    }
    Ok(())
}

fn validate_host_header(host: &str) -> Result<()> {
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(TransportError::Config(
            "httpupgrade: host_header contains whitespace or control bytes".into(),
        ));
    }
    Ok(())
}

fn validate_header_name(name: &str) -> Result<()> {
    if name.is_empty() || !name.bytes().all(is_header_token_byte) {
        return Err(TransportError::Config(format!(
            "httpupgrade: invalid extra header name {name:?}"
        )));
    }
    Ok(())
}

fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(TransportError::Config(format!(
            "httpupgrade: invalid value for extra header {name:?}"
        )));
    }
    Ok(())
}

fn is_header_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

// ─── PrefixedStream ──────────────────────────────────────────────────────────

/// Stream wrapper that yields buffered bytes (payload received in the same
/// reads as the HTTP response headers) before delegating to the inner stream.
/// Writes always go straight through.
struct PrefixedStream {
    prefix: Vec<u8>,
    off: usize,
    inner: Box<dyn Stream>,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.off < this.prefix.len() {
            let avail = &this.prefix[this.off..];
            let take = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..take]);
            this.off += take;
            if this.off >= this.prefix.len() {
                // Fully drained — release the buffer.
                this.prefix = Vec::new();
                this.off = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_headers_count_bounded() {
        // The connect-time backstop for the parse-level `headers` cap
        // (issue #648) — programmatic `HttpUpgradeConfig` construction hits
        // the same bound.
        let mut config = HttpUpgradeConfig {
            extra_headers: (0..=MAX_EXTRA_HEADERS)
                .map(|i| (format!("X-H{i}"), "v".into()))
                .collect(),
            ..HttpUpgradeConfig::default()
        };
        assert!(validate_request_config(&config).is_err());
        config.extra_headers.pop();
        assert!(validate_request_config(&config).is_ok());
    }
}
