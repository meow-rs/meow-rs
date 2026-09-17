//! HTTP CONNECT outbound proxy adapter (M1.B-3).
//!
//! Implements `ProxyAdapter` for `type: http` config entries.  The adapter
//! dials TCP (optionally TLS-wrapped) to the proxy server, sends an HTTP/1.1
//! `CONNECT host:port` request, and returns the tunnelled stream.
//!
//! # Wire format
//!
//! ```text
//! CONNECT {host}:{port} HTTP/1.1\r\n
//! Host: {host}:{port}\r\n
//! [Proxy-Authorization: Basic {base64(user:pass)}\r\n]
//! [{extra_header_k}: {extra_header_v}\r\n ...]
//! \r\n
//! ```
//! Response: `HTTP/1.x {status} ...\r\n[headers]\r\n\r\n`
//! — status 2xx → tunnel open
//! — status 407 → `Err(ProxyAuthFailed)`  (Basic auth only in M1)
//! — other      → `Err(HttpConnectFailed(status))`
//!
//! upstream: `adapter/outbound/http.go`

use async_trait::async_trait;
use base64::Engine as _;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use smol_str::SmolStr;
use std::fmt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::stream_conn::StreamConn;

// ─── Adapter ─────────────────────────────────────────────────────────────────

/// HTTP CONNECT outbound proxy adapter.
///
/// upstream: `adapter/outbound/http.go` — `HttpAdapter`
pub struct HttpAdapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    /// `"server:port"` — returned by `addr()` for relay metadata building.
    addr_str: SmolStr,
    /// `Some((username, password))` — both present or neither (ADR-0002 Class A).
    auth: Option<(String, String)>,
    /// Built once at construction (rustls ClientConfig + root store are
    /// expensive); `TlsLayer::connect` is safe to call concurrently.
    tls_layer: Option<meow_transport::tls::TlsLayer>,
    /// Extra headers injected into the CONNECT request only.
    extra_headers: Vec<(String, String)>,
    health: ProxyHealth,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
}
impl HttpAdapter {
    /// Create an `HttpAdapter`.
    ///
    /// `auth` — `Some((username, password))` for Basic auth; `None` for no auth.
    /// Both username and password must be set or neither (validated at parse time).
    #[allow(
        clippy::too_many_arguments,
        reason = "dialer param for pluggable TcpDialer"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        auth: Option<(String, String)>,
        tls: bool,
        skip_cert_verify: bool,
        extra_headers: Vec<(String, String)>,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Self {
        // Hoisted out of the dial path: TlsLayer::new clones the webpki root
        // store and builds verifier + crypto provider — per-adapter, not
        // per-connection (same pattern as TrojanAdapter::new).
        let tls_layer = tls.then(|| {
            use meow_transport::tls::{TlsConfig, TlsLayer};
            let tls_cfg = TlsConfig {
                skip_cert_verify,
                ..TlsConfig::new(server)
            };
            TlsLayer::new(&tls_cfg)
                .expect("HttpAdapter: failed to build TlsLayer — check TLS config")
        });

        Self {
            name: SmolStr::from(name),
            addr_str: SmolStr::from(format!("{server}:{port}")),
            server: SmolStr::from(server),
            port,
            auth,
            tls_layer,
            extra_headers,
            health: ProxyHealth::new(),
            dialer,
        }
    }

    /// Dial TCP to the proxy server, optionally wrapping in TLS.
    async fn dial_stream(&self) -> Result<Box<dyn meow_transport::Stream>> {
        let tcp = self
            .dialer
            .dial(&self.server, self.port)
            .await
            .map_err(MeowError::Io)?;
        self.wrap_tls(tcp).await
    }

    /// Apply the configured TLS layer to `stream` if `tls: true`.
    /// `stream` must already terminate at this HTTP proxy — `dial_tcp`
    /// obtains it from `dialer.dial`, `connect_over` receives it from the
    /// relay chain.
    async fn wrap_tls(
        &self,
        stream: Box<dyn meow_transport::Stream>,
    ) -> Result<Box<dyn meow_transport::Stream>> {
        if let Some(tls_layer) = &self.tls_layer {
            use meow_transport::Transport;
            tls_layer
                .connect(Box::new(stream))
                .await
                .map_err(|e| MeowError::Proxy(e.to_string()))
        } else {
            Ok(stream)
        }
    }

    /// Run the HTTP CONNECT handshake over `stream`.
    ///
    /// On success the stream is ready for tunnelled application data.
    /// On failure returns the appropriate `MeowError` variant.
    async fn run_connect<S>(
        &self,
        stream: &mut S,
        target: &(dyn fmt::Display + Send + Sync),
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let request = self.build_connect_request(target)?;

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(MeowError::Io)?;

        // ── Read status line ─────────────────────────────────────────────────
        let status_line = read_line(stream).await?;
        let status_str = std::str::from_utf8(&status_line)
            .map_err(|_| MeowError::Proxy("http proxy: non-UTF-8 status line".into()))?
            .trim_end_matches(['\r', '\n']);

        let status_code = parse_http_status(status_str)?;

        match status_code {
            200..=299 => {}
            407 => return Err(MeowError::ProxyAuthFailed),
            code => return Err(MeowError::HttpConnectFailed(code)),
        }

        // ── Drain response headers ───────────────────────────────────────────
        //
        // Cap at 100 headers to guard against a misbehaving proxy sending an
        // unbounded header list that would never emit \r\n\r\n.
        //
        // ADR-0002 Class A divergence: upstream http.go has no explicit cap
        // (relies on Go's default transport limits).
        const MAX_RESPONSE_HEADERS: usize = 100;
        let mut header_count = 0usize;
        loop {
            let line = read_line(stream).await?;
            if line == b"\r\n" {
                break;
            }
            header_count += 1;
            if header_count > MAX_RESPONSE_HEADERS {
                return Err(MeowError::Proxy(format!(
                    "http proxy: response has more than {MAX_RESPONSE_HEADERS} headers"
                )));
            }
        }

        Ok(())
    }

    fn build_connect_request(&self, target: &(dyn fmt::Display + Send + Sync)) -> Result<String> {
        use std::fmt::Write as _;

        let target = target.to_string();
        validate_connect_target(&target)?;

        let extra_len: usize = self
            .extra_headers
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum();
        let mut request = String::with_capacity(64 + target.len() * 2 + extra_len);
        write!(request, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n")
            .expect("writing to String cannot fail");

        if let Some((user, pass)) = &self.auth {
            let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            write!(request, "Proxy-Authorization: Basic {creds}\r\n")
                .expect("writing to String cannot fail");
        }

        for (name, value) in &self.extra_headers {
            validate_header_name(name)?;
            validate_header_value(name, value)?;
            write!(request, "{name}: {value}\r\n").expect("writing to String cannot fail");
        }
        request.push_str("\r\n");
        Ok(request)
    }
}

// ─── ProxyAdapter ─────────────────────────────────────────────────────────────

#[async_trait]
impl ProxyAdapter for HttpAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Http
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let target = connect_target(metadata);
        debug!(
            "http proxy: CONNECT {} via {}:{}",
            target, self.server, self.port
        );

        let mut stream = self.dial_stream().await?;
        self.run_connect(&mut stream, &target).await?;
        Ok(Box::new(StreamConn(stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::NotSupported(
            "http proxy: UDP not supported (HTTP CONNECT is TCP-only)".into(),
        ))
    }

    /// Run the HTTP CONNECT handshake over an already-established stream.
    ///
    /// The stream already terminates at this HTTP proxy — it carries
    /// whichever outer transport the relay's preceding hop established, so
    /// the adapter's own TLS layer (when `tls: true`) still applies before
    /// CONNECT.
    ///
    /// upstream: `adapter/outbound/http.go` — `DialContextWithDialer`
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let target = connect_target(metadata);
        debug!(
            "http proxy: CONNECT (relay) {} over existing stream",
            target
        );
        let mut stream = self.wrap_tls(Box::new(stream)).await?;
        self.run_connect(&mut stream, &target).await?;
        Ok(Box::new(StreamConn(stream)))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Zero-alloc display wrapper for `host:port` from metadata.
///
/// Prefers `metadata.host` (domain name) over raw IP; this preserves the
/// domain name for SNI and logging on the upstream proxy.
fn connect_target(metadata: &Metadata) -> meow_common::AddrDisplay<'_> {
    metadata.remote_address()
}

/// Parse `"HTTP/1.x NNN ..."` → status code as `u16`.
fn parse_http_status(line: &str) -> Result<u16> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(MeowError::Proxy(format!(
            "http proxy: unexpected response line: {line:?}"
        )));
    }
    let code_str = parts.next().unwrap_or("");
    code_str
        .parse::<u16>()
        .map_err(|_| MeowError::Proxy(format!("http proxy: invalid status code: {code_str:?}")))
}

fn validate_connect_target(target: &str) -> Result<()> {
    if target.is_empty() || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(MeowError::Config(
            "http proxy: CONNECT target contains whitespace or control bytes".into(),
        ));
    }
    Ok(())
}

fn validate_header_name(name: &str) -> Result<()> {
    if name.is_empty() || !name.bytes().all(is_header_token_byte) {
        return Err(MeowError::Config(format!(
            "http proxy: invalid extra header name {name:?}"
        )));
    }
    Ok(())
}

fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(MeowError::Config(format!(
            "http proxy: invalid value for extra header {name:?}"
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

/// Read one `\r\n`-terminated line from an async reader.
///
/// Returns the line bytes including the trailing `\r\n`.
/// Errors with `InvalidData` if the line exceeds 8 KiB (guards against a
/// misbehaving proxy sending an infinite stream without a newline).
async fn read_line<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).await.map_err(MeowError::Io)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() > 8192 {
            return Err(MeowError::Proxy(
                "http proxy: response header line too long (> 8 KiB)".into(),
            ));
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    // ─── Helper ──────────────────────────────────────────────────────────────

    /// Spawn a TCP loopback server that replies with `response` verbatim, then
    /// echoes data.  Returns the local address.
    async fn mock_proxy(response: &'static str) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Drain the CONNECT request (read until \r\n\r\n).
            let mut buf = vec![0u8; 4096];
            let mut len = 0;
            loop {
                let n = stream.read(&mut buf[len..]).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                len += n;
                if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Reply with the canned response.
            stream.write_all(response.as_bytes()).await.unwrap();
            // Echo payload.
            let mut echo_buf = [0u8; 256];
            loop {
                match stream.read(&mut echo_buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = stream.write_all(&echo_buf[..n]).await;
                    }
                }
            }
        });

        addr
    }

    fn make_metadata(host: &str, port: u16) -> Metadata {
        Metadata {
            host: host.into(),
            dst_port: port,
            ..Default::default()
        }
    }

    fn make_adapter_no_auth(server: &str, port: u16) -> HttpAdapter {
        HttpAdapter::new(
            server,
            server,
            port,
            None,
            false,
            false,
            vec![],
            Arc::new(crate::dialer::DirectDialer),
        )
    }

    // ─── http_connect_no_auth_succeeds ────────────────────────────────────────
    // upstream: adapter/outbound/http.go::DialContext

    #[tokio::test]
    async fn http_connect_no_auth_succeeds() {
        let addr = mock_proxy("HTTP/1.1 200 Connection established\r\n\r\n").await;
        let adapter = make_adapter_no_auth("127.0.0.1", addr.port());
        let meta = make_metadata("example.com", 443);
        let conn = adapter.dial_tcp(&meta).await.expect("dial_tcp");
        drop(conn); // stream is live
    }

    // ─── http_connect_basic_auth_header_sent ─────────────────────────────────
    // NOT md5 or digest — Basic only.

    #[tokio::test]
    async fn http_connect_basic_auth_header_sent() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (req_tx, req_rx) = tokio::sync::oneshot::channel::<String>();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut len = 0;
            loop {
                let n = stream.read(&mut buf[len..]).await.unwrap_or(0);
                len += n;
                if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if n == 0 {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf[..len]).to_string();
            let _ = req_tx.send(req);
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });

        let adapter = HttpAdapter::new(
            "test",
            "127.0.0.1",
            addr.port(),
            Some(("alice".into(), "s3cr3t".into())),
            false,
            false,
            vec![],
            Arc::new(crate::dialer::DirectDialer),
        );
        let meta = make_metadata("example.com", 443);
        let _ = adapter.dial_tcp(&meta).await.expect("dial_tcp");

        let req = req_rx.await.expect("request captured");
        // Basic base64("alice:s3cr3t") = "YWxpY2U6czNjcjN0"
        let expected_creds = base64::engine::general_purpose::STANDARD.encode("alice:s3cr3t");
        assert!(
            req.contains(&format!("Proxy-Authorization: Basic {expected_creds}")),
            "Basic auth header must be present with correct base64; req=\n{req}"
        );
    }

    // ─── http_connect_407_returns_proxy_auth_failed ───────────────────────────
    // Class A per ADR-0002: 407 is a hard error.

    #[tokio::test]
    async fn http_connect_407_returns_proxy_auth_failed() {
        let addr = mock_proxy("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        let adapter = make_adapter_no_auth("127.0.0.1", addr.port());
        let meta = make_metadata("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::ProxyAuthFailed),
            "407 must map to ProxyAuthFailed; got {err:?}"
        );
    }

    // ─── http_connect_503_returns_http_connect_failed ─────────────────────────
    // NOT panic, NOT timeout.

    #[tokio::test]
    async fn http_connect_503_returns_http_connect_failed() {
        let addr = mock_proxy("HTTP/1.1 503 Service Unavailable\r\n\r\n").await;
        let adapter = make_adapter_no_auth("127.0.0.1", addr.port());
        let meta = make_metadata("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::HttpConnectFailed(503)),
            "503 must map to HttpConnectFailed(503); got {err:?}"
        );
    }

    // ─── http_extra_headers_injected ─────────────────────────────────────────

    #[tokio::test]
    async fn http_extra_headers_injected() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (req_tx, req_rx) = tokio::sync::oneshot::channel::<String>();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut len = 0;
            loop {
                let n = stream.read(&mut buf[len..]).await.unwrap_or(0);
                len += n;
                if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if n == 0 {
                    break;
                }
            }
            let _ = req_tx.send(String::from_utf8_lossy(&buf[..len]).to_string());
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });

        let adapter = HttpAdapter::new(
            "test",
            "127.0.0.1",
            addr.port(),
            None,
            false,
            false,
            vec![("X-Foo".into(), "bar".into())],
            Arc::new(crate::dialer::DirectDialer),
        );
        let meta = make_metadata("example.com", 443);
        let _ = adapter.dial_tcp(&meta).await.expect("dial_tcp");

        let req = req_rx.await.expect("request captured");
        assert!(
            req.contains("X-Foo: bar"),
            "extra header X-Foo must appear in CONNECT request; req=\n{req}"
        );
    }

    #[tokio::test]
    async fn http_extra_headers_reject_crlf_in_value() {
        let adapter = HttpAdapter::new(
            "test",
            "127.0.0.1",
            8080,
            None,
            false,
            false,
            vec![("X-Foo".into(), "bar\r\nX-Injected: yes".into())],
            Arc::new(crate::dialer::DirectDialer),
        );
        let (mut client, _server) = tokio::io::duplex(64);
        let target = "example.com:443";
        let err = adapter
            .run_connect(&mut client, &target)
            .await
            .expect_err("invalid header must error");
        assert!(
            matches!(err, MeowError::Config(ref msg) if msg.contains("X-Foo")),
            "expected config error naming X-Foo, got {err:?}"
        );
    }

    #[tokio::test]
    async fn http_extra_headers_are_not_truncated() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (req_tx, req_rx) = tokio::sync::oneshot::channel::<String>();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let n = stream.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = req_tx.send(String::from_utf8_lossy(&buf).to_string());
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });

        let long_value = "a".repeat(1500);
        let adapter = HttpAdapter::new(
            "test",
            "127.0.0.1",
            addr.port(),
            None,
            false,
            false,
            vec![("X-Long".into(), long_value.clone())],
            Arc::new(crate::dialer::DirectDialer),
        );
        let meta = make_metadata("example.com", 443);
        let _ = adapter.dial_tcp(&meta).await.expect("dial_tcp");

        let req = req_rx.await.expect("request captured");
        assert!(
            req.contains(&format!("X-Long: {long_value}\r\n\r\n")),
            "full long header and terminator must be present; len={}",
            req.len()
        );
    }

    // ─── http_response_header_count_exceeded_returns_error ───────────────────
    // Pre-VLESS hardening (M1.B-3): > 100 response headers → Proxy error.
    // NOT infinite drain. NOT connection hang.
    // ADR-0002 Class A divergence: upstream http.go has no explicit header cap.

    #[tokio::test]
    async fn http_response_header_count_exceeded_returns_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Drain the CONNECT request.
            let mut buf = vec![0u8; 4096];
            let mut len = 0;
            loop {
                let n = stream.read(&mut buf[len..]).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                len += n;
                if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // 200 status + 101 headers (exceeds the 100-header cap) + blank line.
            let mut resp = String::from("HTTP/1.1 200 Connection established\r\n");
            for i in 0..101usize {
                let _ = write!(resp, "X-Flood-{i}: value\r\n");
            }
            resp.push_str("\r\n");
            let _ = stream.write_all(resp.as_bytes()).await;
        });

        let adapter = make_adapter_no_auth("127.0.0.1", addr.port());
        let meta = make_metadata("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MeowError::Proxy(ref msg) if msg.contains("more than 100 headers")),
            "101 response headers must trigger the cap error; got {err:?}"
        );
    }

    // ─── http_connect_over_relay ─────────────────────────────────────────────
    // connect_over runs the handshake over an existing stream (relay chain),
    // NOT a fresh TCP connect.

    #[tokio::test]
    async fn http_connect_over_relay() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // drain request
            let mut buf = [0u8; 4096];
            let mut len = 0;
            loop {
                let n = stream.read(&mut buf[len..]).await.unwrap_or(0);
                len += n;
                if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if n == 0 {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            // echo
            let mut echo = [0u8; 256];
            loop {
                match stream.read(&mut echo).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = stream.write_all(&echo[..n]).await;
                    }
                }
            }
        });

        // Establish the "outer" connection (simulating a relay's first hop).
        let tcp = TcpStream::connect(addr).await.unwrap();
        let outer: Box<dyn ProxyConn> = Box::new(tcp);

        let adapter = make_adapter_no_auth("127.0.0.1", addr.port());
        let meta = make_metadata("example.com", 443);

        // connect_over must NOT dial a new TCP connection.
        let mut conn = adapter
            .connect_over(outer, &meta)
            .await
            .expect("connect_over");

        // Verify the tunnel is live.
        conn.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    // ─── parse_http_status ────────────────────────────────────────────────────

    #[test]
    fn parse_http_status_cases() {
        // (label, response line, expected): `Some(code)` => `Ok(code)`, `None` => `Err`.
        let cases: &[(&str, &str, Option<u16>)] = &[
            ("200 ok", "HTTP/1.1 200 OK", Some(200)),
            (
                "407 proxy auth required",
                "HTTP/1.0 407 Proxy Auth Required",
                Some(407),
            ),
            ("bad line", "GARBAGE", None),
        ];

        // Collect instead of asserting inline so every case runs even if one fails.
        let mut failures = Vec::new();
        for &(label, line, expected) in cases {
            match (parse_http_status(line), expected) {
                (Ok(code), Some(want)) if code == want => {}
                (Err(_), None) => {}
                (got, want) => failures.push(format!(
                    "case {label:?}: parse_http_status({line:?}) expected {want:?}, got {got:?}"
                )),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
