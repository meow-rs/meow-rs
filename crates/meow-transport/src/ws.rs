//! WebSocket transport layer.
//!
//! [`WsLayer`] wraps an established byte-stream (TCP or TLS) with a WebSocket
//! upgrade handshake, producing a new [`Stream`] that frames bytes as
//! binary WebSocket messages.
//!
//! # Early data
//!
//! When `max_early_data > 0`, the first `min(write_len, max_early_data)` bytes
//! of the first caller write are base64url-encoded (no padding) and sent in the
//! HTTP upgrade request as the value of `early_data_header_name` (defaults to
//! `"Sec-WebSocket-Protocol"`).  This matches upstream
//! `transport/vmess/websocket.go` byte-for-byte.
//!
//! The upgrade is *deferred* until the early-data buffer is full **or** the
//! caller flushes / reads.  `max_early_data = 0` (default) does the upgrade
//! eagerly inside [`Transport::connect`].

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::{Sink, Stream as FuturesStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::tungstenite::Bytes;
use tokio_tungstenite::WebSocketStream;
use tracing::warn;

use crate::{Result, Stream, Transport, TransportError};

/// Footprint-bounded WebSocket config (tungstenite defaults to a 128 KiB
/// write buffer per connection and 64 MiB max message, which inflates RSS at
/// high concurrency). 4 KiB matches `RELAY_BUF_SIZE` and is plenty for the
/// streaming-relay use case where each write is a single relay-buf chunk.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .write_buffer_size(4 * 1024)
        .max_write_buffer_size(64 * 1024)
        .max_message_size(Some(4 * 1024 * 1024))
        .max_frame_size(Some(1024 * 1024))
        .accept_unmasked_frames(false)
}

// ─── Public types ────────────────────────────────────────────────────────────

/// Early-data ceiling: 2048 bytes is the conventional value (the Xray /
/// sing-box default; upstream mihomo itself leaves `max-early-data`
/// unbounded — we cap deliberately). The deferred-upgrade buffer holds up
/// to this many caller bytes before the handshake completes — enforced at
/// config parse *and* at connect time (issue #648).
pub const MAX_WS_EARLY_DATA: usize = 2048;

/// Configuration for the WebSocket transport layer.
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// HTTP request path for the WebSocket upgrade.  Defaults to `"/"`.
    pub path: String,
    /// Value for the `Host` header.  If also present in
    /// [`extra_headers`](WsConfig::extra_headers), `host_header` wins
    /// (with a `warn!`).
    pub host_header: Option<String>,
    /// Additional HTTP headers sent in the upgrade request.
    /// `Host` entries here are silently dropped if `host_header` is also set
    /// (after logging a warning).
    pub extra_headers: Vec<(String, String)>,
    /// Maximum bytes to send as early data in the upgrade request header.
    /// `0` (default) disables early data — the safe default.
    /// Clamped to [`MAX_WS_EARLY_DATA`]: `meow-config` clamps at parse
    /// time and this crate clamps again at connect time (issue #648).
    pub max_early_data: usize,
    /// HTTP header name for the early data value.
    /// Defaults to `"Sec-WebSocket-Protocol"` (upstream convention).
    pub early_data_header_name: Option<String>,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            host_header: None,
            extra_headers: Vec::new(),
            max_early_data: 0,
            early_data_header_name: None,
        }
    }
}

// ─── WsLayer ─────────────────────────────────────────────────────────────────

/// Transport layer that upgrades an inner stream to WebSocket.
///
/// Wrap a TCP or TLS stream with [`Transport::connect`] to obtain a new stream
/// that frames bytes as WebSocket binary messages.
pub struct WsLayer {
    config: WsConfig,
}

impl WsLayer {
    /// Create a `WsLayer` from the given configuration.
    ///
    /// Returns `Err` if:
    /// - `host_header` is `None` — normalization (fallback to the proxy's
    ///   `server:` address) is the caller's responsibility; `meow-transport`
    ///   does not infer values from context it cannot see (ADR-0001 §1).
    /// - any key/value in `extra_headers` is not a valid HTTP header name/value —
    ///   caught here at construction time so the error surfaces as a config
    ///   error rather than a panic mid-connection.
    ///
    /// Logs a `warn!` if both `host_header` and a `Host` entry in
    /// `extra_headers` are set — the conflict is detectable at construction
    /// time and warning once here avoids per-connection spam.
    pub fn new(config: WsConfig) -> Result<Self> {
        // F1: require host_header (ADR-0001 §1 — transport never infers values).
        if config.host_header.is_none() {
            return Err(TransportError::Config(
                "ws: host_header must be set; \
                 fall back to the proxy server address in the config layer"
                    .into(),
            ));
        }

        let host = config
            .host_header
            .as_deref()
            .expect("host_header checked above");
        let uri = format!("ws://{}{}", host, config.path);
        let early_header = config
            .early_data_header_name
            .as_deref()
            .unwrap_or("Sec-WebSocket-Protocol");
        let early_value = if config.max_early_data > 0 {
            "ZWFybHk"
        } else {
            ""
        };

        // F2: validate the actual request shape at construction time.
        // build_request can fail on InvalidUri, InvalidHeaderName, or
        // InvalidHeaderValue; catching it here means begin_upgrade cannot panic
        // on deferred early-data connections.
        build_request(&uri, host, &config.extra_headers, early_header, early_value)
            .map_err(|e| TransportError::Config(format!("ws: invalid request config: {e}")))?;

        let host_in_extra = config
            .extra_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("host"));
        if host_in_extra && config.host_header.is_some() {
            warn!(
                "ws: both host_header and extra_headers[\"Host\"] are set; \
                 host_header wins (extra Host entry dropped)"
            );
        }
        Ok(Self { config })
    }
}

#[async_trait]
impl Transport for WsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        // Invariant: host_header is Some — enforced by WsLayer::new.
        let host = self
            .config
            .host_header
            .as_deref()
            .expect("host_header validated at WsLayer::new")
            .to_owned();
        let uri = format!("ws://{}{}", host, self.config.path);

        // Strip any Host from extra_headers; we add it explicitly.
        let extra: Vec<(String, String)> = self
            .config
            .extra_headers
            .iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("host"))
            .cloned()
            .collect();

        // Clamp the early-data cap here too — the early bytes are buffered
        // then base64'd into a single header, so an unclamped programmatic
        // config would write an unbounded header (issue #648).
        let max_early_data = self.config.max_early_data.min(MAX_WS_EARLY_DATA);
        if self.config.max_early_data > MAX_WS_EARLY_DATA {
            warn!(
                "ws max-early-data {} exceeds the {MAX_WS_EARLY_DATA}-byte ceiling; clamped",
                self.config.max_early_data
            );
        }
        let early_header = self
            .config
            .early_data_header_name
            .clone()
            .unwrap_or_else(|| "Sec-WebSocket-Protocol".into());

        if max_early_data == 0 {
            // Eager path — no early data.
            let request = build_request(&uri, &host, &extra, "", "")
                .map_err(|e| TransportError::Config(e.to_string()))?;
            let (ws, _) =
                tokio_tungstenite::client_async_with_config(request, inner, Some(ws_config()))
                    .await
                    .map_err(|e| TransportError::WebSocket(e.to_string()))?;
            Ok(Box::new(WsStream::connected(ws)))
        } else {
            // Deferred path — accumulate early data on first writes.
            Ok(Box::new(WsStream::pending(
                inner,
                uri,
                host,
                extra,
                max_early_data,
                early_header,
            )))
        }
    }
}

// ─── Request builder ─────────────────────────────────────────────────────────

fn build_request(
    uri: &str,
    host: &str,
    extra_headers: &[(String, String)],
    early_data_header: &str,
    early_data_value: &str,
) -> std::result::Result<
    tokio_tungstenite::tungstenite::http::Request<()>,
    tokio_tungstenite::tungstenite::http::Error,
> {
    // Required WebSocket upgrade headers (RFC 6455).
    let mut builder = tokio_tungstenite::tungstenite::http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        );

    for (k, v) in extra_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !early_data_value.is_empty() {
        builder = builder.header(early_data_header, early_data_value);
    }

    builder.body(())
}

// ─── WsStream ────────────────────────────────────────────────────────────────

type BoxStream = Box<dyn Stream>;

// The upgrade future runs in a spawned task and sends the result back.
// Using a oneshot channel avoids boxing a non-Sync future while still making
// WsStream: Sync (oneshot::Receiver<T>: Sync when T: Send).
type UpgradeRx = tokio::sync::oneshot::Receiver<
    std::result::Result<WebSocketStream<BoxStream>, tokio_tungstenite::tungstenite::Error>,
>;

struct PendingState {
    inner: Option<BoxStream>,
    uri: String,
    host: String,
    extra_headers: Vec<(String, String)>,
    early_buf: Vec<u8>,
    max_early_data: usize,
    early_header_name: String,
}

struct ConnectedState {
    ws: WebSocketStream<BoxStream>,
    /// Payload of the last Binary frame, held as received (`Bytes`) and
    /// drained by `poll_read` — no copy into an intermediate Vec.
    read_buf: Bytes,
    read_pos: usize,
}

enum WsInner {
    Pending(Box<PendingState>),
    /// Upgrade in progress; result delivered via the channel.
    Upgrading(UpgradeRx),
    Connected(Box<ConnectedState>),
}

struct WsStream {
    inner: WsInner,
}

impl WsStream {
    fn connected(ws: WebSocketStream<BoxStream>) -> Self {
        Self {
            inner: WsInner::Connected(Box::new(ConnectedState {
                ws,
                read_buf: Bytes::new(),
                read_pos: 0,
            })),
        }
    }

    fn pending(
        inner: BoxStream,
        uri: String,
        host: String,
        extra_headers: Vec<(String, String)>,
        max_early_data: usize,
        early_header_name: String,
    ) -> Self {
        Self {
            inner: WsInner::Pending(Box::new(PendingState {
                inner: Some(inner),
                uri,
                host,
                extra_headers,
                early_buf: Vec::new(),
                max_early_data,
                early_header_name,
            })),
        }
    }
}

/// Transition `state` → `WsInner::Upgrading` by spawning the handshake task.
fn begin_upgrade(state: &mut PendingState) -> UpgradeRx {
    let inner = state.inner.take().expect("inner stream taken only once");
    let early_value = if state.early_buf.is_empty() {
        String::new()
    } else {
        URL_SAFE_NO_PAD.encode(&state.early_buf)
    };
    let request = build_request(
        &state.uri,
        &state.host,
        &state.extra_headers,
        &state.early_header_name,
        &early_value,
    )
    .expect("WsConfig produces a valid HTTP upgrade request");

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result =
            tokio_tungstenite::client_async_with_config(request, inner, Some(ws_config())).await;
        let _ = tx.send(result.map(|(ws, _)| ws));
    });
    rx
}

// ─── Poll helpers ─────────────────────────────────────────────────────────────

/// Poll the upgrade channel; on success, replace `inner` with a `Connected`
/// state.  Returns `Poll::Pending` while the handshake is in progress, or
/// `Poll::Ready(Err(_))` on failure.
///
/// Returns `Poll::Ready(Ok(()))` when `inner` has been replaced with
/// `WsInner::Connected`.
fn poll_upgrade(inner: &mut WsInner, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let WsInner::Upgrading(rx) = inner else {
        unreachable!("poll_upgrade called outside Upgrading state")
    };
    match Pin::new(rx).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(Ok(ws))) => {
            *inner = WsInner::Connected(Box::new(ConnectedState {
                ws,
                read_buf: Bytes::new(),
                read_pos: 0,
            }));
            Poll::Ready(Ok(()))
        }
        Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
        Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::other("ws upgrade task dropped"))),
    }
}

// ─── AsyncRead ───────────────────────────────────────────────────────────────

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut self.inner {
                WsInner::Pending(state) => {
                    // A read forces the upgrade to start (with whatever
                    // early data has been buffered so far).
                    let rx = begin_upgrade(state);
                    self.inner = WsInner::Upgrading(rx);
                }
                WsInner::Upgrading(_) => {
                    match poll_upgrade(&mut self.inner, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => { /* now Connected, loop */ }
                    }
                }
                WsInner::Connected(state) => {
                    // Drain leftover bytes from the previous frame.
                    if state.read_pos < state.read_buf.len() {
                        let rem = &state.read_buf[state.read_pos..];
                        let n = rem.len().min(buf.remaining());
                        buf.put_slice(&rem[..n]);
                        state.read_pos += n;
                        if state.read_pos == state.read_buf.len() {
                            state.read_buf.clear();
                            state.read_pos = 0;
                        }
                        return Poll::Ready(Ok(()));
                    }

                    // Poll next WebSocket message.
                    let msg = match Pin::new(&mut state.ws).poll_next(cx) {
                        Poll::Ready(x) => x,
                        Poll::Pending => return Poll::Pending,
                    };
                    match msg {
                        None => return Poll::Ready(Ok(())), // EOF
                        Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                        Some(Ok(Message::Binary(data))) => {
                            state.read_buf = data;
                            state.read_pos = 0;
                            // loop to drain
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            // Best-effort pong: only attempt when the sink is
                            // immediately ready.  Per the Sink contract,
                            // start_send must not be called unless poll_ready
                            // returned Ready(Ok(())).  Dropping a pong when
                            // the queue is briefly full is acceptable for an
                            // optional keepalive; blocking the read path is not.
                            if let Poll::Ready(Ok(())) = Pin::new(&mut state.ws).poll_ready(cx) {
                                let _ = Pin::new(&mut state.ws).start_send(Message::Pong(payload));
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        Some(Ok(Message::Text(_))) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "ws: unexpected text frame",
                            )));
                        }
                        Some(Ok(Message::Pong(_) | Message::Frame(_))) => {
                            // Pong replies and raw frames are noise on the read
                            // path; ignore and poll for the next frame.
                        }
                    }
                }
            }
        }
    }
}

// ─── AsyncWrite ──────────────────────────────────────────────────────────────

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match &mut self.inner {
                WsInner::Pending(state) => {
                    let remaining = state.max_early_data - state.early_buf.len();
                    let take = remaining.min(buf.len());
                    state.early_buf.extend_from_slice(&buf[..take]);

                    if state.early_buf.len() >= state.max_early_data {
                        // Buffer full — start the upgrade.
                        let rx = begin_upgrade(state);
                        self.inner = WsInner::Upgrading(rx);
                        // Return the bytes consumed so far; any overflow
                        // will be written in the next poll_write call.
                        return Poll::Ready(Ok(take));
                    }
                    // Buffer not yet full; report bytes accepted.
                    return Poll::Ready(Ok(take));
                }
                WsInner::Upgrading(_) => {
                    match poll_upgrade(&mut self.inner, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => { /* now Connected, loop */ }
                    }
                }
                WsInner::Connected(state) => {
                    match Pin::new(&mut state.ws).poll_ready(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(io::Error::other(e)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                    // ADR-0008 HP-3: one `Bytes::copy_from_slice` per
                    // WS-relayed chunk. With tokio-tungstenite >=0.26 the
                    // `Bytes` payload is uniquely owned, so tungstenite masks
                    // it in place (`try_into_mut`) instead of re-copying the
                    // frame — one allocation per chunk, down from the 0.24
                    // `Vec<u8>` copy + internal re-copy.
                    if let Err(e) = Pin::new(&mut state.ws)
                        .start_send(Message::Binary(Bytes::copy_from_slice(buf)))
                    {
                        return Poll::Ready(Err(io::Error::other(e)));
                    }
                    // Drive the queued frame onto the wire. tokio-tungstenite's
                    // Sink buffers messages internally — without an explicit
                    // poll_flush here, a lone write (SS sends one address+payload
                    // packet then awaits a read) sits in the sink forever and
                    // both sides deadlock.
                    match Pin::new(&mut state.ws).poll_flush(cx) {
                        Poll::Ready(Ok(())) | Poll::Pending => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                    }
                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.inner {
                WsInner::Pending(state) => {
                    // Flush forces the upgrade (with buffered early data).
                    let rx = begin_upgrade(state);
                    self.inner = WsInner::Upgrading(rx);
                }
                WsInner::Upgrading(_) => {
                    match poll_upgrade(&mut self.inner, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => { /* now Connected, loop */ }
                    }
                }
                WsInner::Connected(state) => {
                    return Pin::new(&mut state.ws)
                        .poll_flush(cx)
                        .map_err(io::Error::other);
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.inner {
                WsInner::Pending(state) => {
                    let rx = begin_upgrade(state);
                    self.inner = WsInner::Upgrading(rx);
                }
                WsInner::Upgrading(_) => match poll_upgrade(&mut self.inner, cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                },
                WsInner::Connected(state) => {
                    return Pin::new(&mut state.ws)
                        .poll_close(cx)
                        .map_err(io::Error::other);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> WsConfig {
        WsConfig {
            path: "/".into(),
            host_header: Some("example.com".into()),
            extra_headers: Vec::new(),
            max_early_data: 0,
            early_data_header_name: None,
        }
    }

    fn assert_invalid_config(config: WsConfig, expected: &str) {
        let Err(err) = WsLayer::new(config) else {
            panic!("invalid websocket config unexpectedly succeeded");
        };
        match err {
            TransportError::Config(msg) => {
                assert!(
                    msg.contains(expected),
                    "expected config error containing {expected:?}, got: {msg}"
                );
            }
            other => panic!("expected TransportError::Config, got: {other:?}"),
        }
    }

    #[test]
    fn ws_new_rejects_crlf_in_path_before_deferred_upgrade() {
        let mut config = valid_config();
        config.path = "/ok\r\nX-Injected: yes".into();
        config.max_early_data = 1;

        assert_invalid_config(config, "invalid request config");
    }

    #[test]
    fn ws_new_rejects_crlf_in_host_header() {
        let mut config = valid_config();
        config.host_header = Some("good.example\r\nX-Injected: yes".into());

        assert_invalid_config(config, "invalid request config");
    }

    #[test]
    fn ws_new_rejects_invalid_early_data_header_name() {
        let mut config = valid_config();
        config.max_early_data = 1;
        config.early_data_header_name = Some("Bad Header".into());

        assert_invalid_config(config, "invalid request config");
    }
}
