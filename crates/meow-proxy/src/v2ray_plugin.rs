//! Built-in `v2ray-plugin` SIP003 client transport (M1.A-2 migration).
//!
//! Implements the WebSocket (and optional TLS) transport used by the
//! `v2ray-plugin` SIP003 plugin for Shadowsocks, natively in Rust.
//!
//! TLS is provided by `meow_transport::tls::TlsLayer`; WebSocket by
//! `meow_transport::ws::WsLayer`.  Protocol logic (SIP003 option parsing,
//! `mux` pass-through) remains here unchanged.
//!
//! Entry points:
//! - [`parse_opts`] converts a SIP003 `k=v;k=v` opts string into a
//!   [`V2rayPluginConfig`].
//! - [`dial`] opens a TCP (optionally TLS) + WebSocket stream to the server
//!   and returns a `Box<dyn meow_transport::Stream>` that callers layer
//!   Shadowsocks encryption on top of via `ProxyClientStream::from_stream`.

use std::collections::HashMap;

use meow_common::{MeowError, Result};
use meow_transport::{
    tls::{TlsConfig, TlsLayer},
    ws::{WsConfig, WsLayer},
    Transport,
};
use tracing::{debug, warn};

use crate::transport_to_proxy_err;

/// Transport mode.  Only WebSocket is supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Websocket,
}

/// Parsed v2ray-plugin client options.
#[derive(Debug, Clone)]
pub struct V2rayPluginConfig {
    pub mode: Mode,
    pub tls: bool,
    /// Host header and TLS SNI.  Falls back to the SS server address if not
    /// set in the opts string.
    pub host: String,
    /// WebSocket upgrade path.  Defaults to `/`.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub skip_cert_verify: bool,
    /// Parsed but not acted on (matches Go mihomo's built-in plugin behaviour).
    /// NOTE: setting `mux=1` on the *server* side requires `mux=0` (the
    /// default) in the client opts; the v2ray-plugin server expects plain
    /// WebSocket frames, not real SMUX streams.  Leaving `mux=false` here is
    /// the correct default for `mode=websocket` without a real MUX engine.
    pub mux: bool,
}

impl Default for V2rayPluginConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Websocket,
            tls: false,
            host: String::new(),
            path: "/".to_string(),
            headers: HashMap::new(),
            skip_cert_verify: false,
            mux: false,
        }
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Parse a SIP003 opts string (`mode=websocket;tls;host=...;path=/ws;mux=1`).
///
/// - Bare keys (e.g. `tls`) are treated as `key=true`.
/// - Unknown keys are logged at `warn` level and ignored.
/// - Only `mode=websocket` is accepted; other modes return an error.
pub fn parse_opts(s: &str) -> Result<V2rayPluginConfig> {
    let mut cfg = V2rayPluginConfig::default();

    for token in s.split(';').map(str::trim).filter(|t| !t.is_empty()) {
        let (key, value) = match token.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim().to_string()),
            None => (token, "true".to_string()),
        };

        match key {
            "mode" => {
                if value.eq_ignore_ascii_case("websocket") || value.eq_ignore_ascii_case("ws") {
                    cfg.mode = Mode::Websocket;
                } else {
                    return Err(MeowError::Config(format!(
                        "v2ray-plugin: unsupported mode '{value}' (only 'websocket' is supported)"
                    )));
                }
            }
            "tls" => cfg.tls = parse_bool(&value),
            "host" => cfg.host = value,
            "path" => cfg.path = value,
            "mux" => cfg.mux = parse_bool(&value),
            "skip-cert-verify" => cfg.skip_cert_verify = parse_bool(&value),
            "header" => {
                // Form: header=Key:Value
                if let Some((k, v)) = value.split_once(':') {
                    cfg.headers
                        .insert(k.trim().to_string(), v.trim().to_string());
                } else {
                    warn!("v2ray-plugin: malformed header entry '{}'", value);
                }
            }
            other => {
                warn!("v2ray-plugin: ignoring unknown opt '{}'", other);
            }
        }
    }

    Ok(cfg)
}

/// Build a reusable `TlsLayer` for a v2ray-plugin config with `tls=true`.
///
/// Call once at adapter construction time. Returns `None` when TLS is disabled.
pub fn build_tls_layer(cfg: &V2rayPluginConfig) -> Result<Option<TlsLayer>> {
    if !cfg.tls {
        return Ok(None);
    }
    let tls_config = TlsConfig {
        skip_cert_verify: cfg.skip_cert_verify,
        ..TlsConfig::new(cfg.host.clone())
    };
    TlsLayer::new(&tls_config)
        .map(Some)
        .map_err(transport_to_proxy_err)
}

/// Dial a TCP (+ optional TLS) + WebSocket connection to `server_host:server_port`
/// and return the framed stream ready to be wrapped by the SS encryption layer.
///
/// When `tls_layer` is `Some`, it is reused across connections so the
/// BoringSSL `SSL_CTX` and root cert store are allocated only once.
pub async fn dial(
    cfg: &V2rayPluginConfig,
    tls_layer: Option<&TlsLayer>,
    server_host: &str,
    server_port: u16,
    dialer: &dyn crate::dialer::TcpDialer,
) -> Result<Box<dyn meow_transport::Stream>> {
    // 1) Raw TCP.
    let tcp = dialer
        .dial(server_host, server_port)
        .await
        .map_err(MeowError::Io)?;

    handshake_over(cfg, tls_layer, server_host, server_port, tcp).await
}

/// Apply the optional TLS handshake + WebSocket upgrade on `stream`, which
/// must already terminate at `server_host:server_port` — `dial` obtains it
/// from `dialer.dial`, the SS adapter's `connect_over` receives it from the
/// relay chain.
pub async fn handshake_over(
    cfg: &V2rayPluginConfig,
    tls_layer: Option<&TlsLayer>,
    server_host: &str,
    server_port: u16,
    stream: Box<dyn meow_transport::Stream>,
) -> Result<Box<dyn meow_transport::Stream>> {
    let host_header = if cfg.host.is_empty() {
        server_host.to_string()
    } else {
        cfg.host.clone()
    };

    debug!(
        "v2ray-plugin: dialing {}:{} tls={} host={} path={} mux={}",
        server_host, server_port, cfg.tls, host_header, cfg.path, cfg.mux
    );

    // 2) Optional TLS handshake via the pre-built TlsLayer.
    let stream: Box<dyn meow_transport::Stream> = if let Some(tls) = tls_layer {
        tls.connect(Box::new(stream))
            .await
            .map_err(transport_to_proxy_err)?
    } else {
        stream
    };

    // 3) WebSocket upgrade via WsLayer.
    let extra_headers: Vec<(String, String)> = cfg
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let ws_config = WsConfig {
        path: cfg.path.clone(),
        // host_header wins over any Host entry in cfg.headers (WsLayer warns if
        // both are set — that's a user misconfiguration, not a code bug).
        host_header: Some(host_header),
        extra_headers,
        ..WsConfig::default()
    };
    let ws_layer = WsLayer::new(ws_config).map_err(transport_to_proxy_err)?;
    ws_layer
        .connect(stream)
        .await
        .map_err(transport_to_proxy_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_opts_cases() {
        struct Case {
            name: &'static str,
            input: &'static str,
            /// `None` means `parse_opts` must return `Err`.
            expect: Option<V2rayPluginConfig>,
        }

        let cases = [
            Case {
                name: "websocket_mux",
                input: "mode=websocket;mux=1;host=example.com;path=/ws",
                expect: Some(V2rayPluginConfig {
                    mode: Mode::Websocket,
                    tls: false,
                    host: "example.com".to_string(),
                    path: "/ws".to_string(),
                    headers: Default::default(),
                    skip_cert_verify: false,
                    mux: true,
                }),
            },
            Case {
                name: "tls_websocket_mux_skip_verify",
                input: "mode=websocket;tls;mux=1;host=example.com;path=/ws;skip-cert-verify=true",
                expect: Some(V2rayPluginConfig {
                    mode: Mode::Websocket,
                    tls: true,
                    host: "example.com".to_string(),
                    path: "/ws".to_string(),
                    headers: Default::default(),
                    skip_cert_verify: true,
                    mux: true,
                }),
            },
            Case {
                name: "defaults_on_empty",
                input: "",
                expect: Some(V2rayPluginConfig {
                    mode: Mode::Websocket,
                    tls: false,
                    host: String::new(),
                    path: "/".to_string(),
                    headers: Default::default(),
                    skip_cert_verify: false,
                    mux: false,
                }),
            },
            Case {
                name: "bare_tls_and_mux",
                input: "tls;mux",
                expect: Some(V2rayPluginConfig {
                    mode: Mode::Websocket,
                    tls: true,
                    host: String::new(),
                    path: "/".to_string(),
                    headers: Default::default(),
                    skip_cert_verify: false,
                    mux: true,
                }),
            },
            Case {
                name: "unknown_key_ignored",
                input: "mode=websocket;foo=bar;path=/ws",
                expect: Some(V2rayPluginConfig {
                    mode: Mode::Websocket,
                    tls: false,
                    host: String::new(),
                    path: "/ws".to_string(),
                    headers: Default::default(),
                    skip_cert_verify: false,
                    mux: false,
                }),
            },
            Case {
                name: "header_opt",
                input: "mode=websocket;header=X-Foo:bar;host=example.com",
                expect: Some(V2rayPluginConfig {
                    mode: Mode::Websocket,
                    tls: false,
                    host: "example.com".to_string(),
                    path: "/".to_string(),
                    headers: [("X-Foo".to_string(), "bar".to_string())]
                        .into_iter()
                        .collect(),
                    skip_cert_verify: false,
                    mux: false,
                }),
            },
            Case {
                name: "bad_mode_errors",
                input: "mode=quic",
                expect: None,
            },
        ];

        let mut failures = Vec::new();
        for case in &cases {
            match (parse_opts(case.input), case.expect.as_ref()) {
                (Ok(cfg), Some(want)) => {
                    if cfg.mode != want.mode
                        || cfg.tls != want.tls
                        || cfg.host != want.host
                        || cfg.path != want.path
                        || cfg.headers != want.headers
                        || cfg.skip_cert_verify != want.skip_cert_verify
                        || cfg.mux != want.mux
                    {
                        failures.push(format!("{}: got {cfg:?}, want {want:?}", case.name));
                    }
                }
                (Ok(cfg), None) => {
                    failures.push(format!("{}: expected Err, got Ok({cfg:?})", case.name));
                }
                (Err(e), Some(_)) => {
                    failures.push(format!("{}: expected Ok, got Err({e})", case.name));
                }
                (Err(_), None) => {}
            }
        }

        assert!(
            failures.is_empty(),
            "parse_opts case failures:\n{}",
            failures.join("\n")
        );
    }
}
