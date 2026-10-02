//! Reusable composable stream-transport layers for meow-rs.
//!
//! Each layer wraps an inner [`Box<dyn Stream>`] and produces a new one.
//! Layers compose by chaining [`Transport::connect`] calls:
//!
//! ```text
//! let tcp:  Box<dyn Stream> = tcp_connect(addr).await?;
//! let s     = tls_layer.connect(tcp).await?;
//! let s     = ws_layer.connect(s).await?;
//! // `s` is handed to the VMess/VLESS protocol codec
//! ```
//!
//! Architecture: [ADR-0001](../../docs/adr/0001-meow-transport-crate.md).
//!
//! # Crate boundary invariants (enforced by CI)
//!
//! * No dependency on any other workspace crate (`meow-common`, `meow-proxy`,
//!   `meow-dns`, `meow-config`). This crate is a protocol-agnostic leaf.
//! * No `anyhow::Error` in any public function signature — only [`TransportError`].
//! * No server-side code (`accept`/`bind`/`listen`/`TcpListener`) in `src/`.
//!   Test helpers in `tests/support/` are whitelisted.

use std::any::Any;

use tokio::io::{AsyncRead, AsyncWrite};

pub use error::TransportError;

/// Upper bound on remote-supplied HTTP extra-header lists —
/// `xhttp-opts.headers` and `http-upgrade-opts.headers` alike. A giant
/// `headers` map is attacker-chosen process memory; 64 is far beyond any
/// real deployment (issue #648). Re-exported by the per-transport modules
/// so config parsers can name the bound locally.
pub const MAX_EXTRA_HEADERS: usize = 64;

mod error;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(all(feature = "tls", feature = "reality"))]
mod reality_hello;
#[cfg(all(feature = "tls", feature = "reality"))]
mod reality_tls;

#[cfg(feature = "ws")]
pub mod ws;

#[cfg(any(feature = "grpc", feature = "h2", feature = "xhttp"))]
pub mod h2_common;

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "h2")]
pub mod h2;

#[cfg(feature = "httpupgrade")]
pub mod httpupgrade;

#[cfg(feature = "xhttp")]
pub mod xhttp;

/// Shared TLS-record assembly / outbox machinery for the record-framed
/// SIP003 transports (`shadow_tls`, `restls`, `jls`).
#[cfg(any(feature = "shadow-tls", feature = "restls", feature = "jls"))]
mod record_io;

/// shadow-tls client transport (v1/v2/v3) — real cover TLS handshake over
/// a sniffer/patcher shim, then record-framed data.  Used by the
/// `shadow-tls` Shadowsocks plugin in `meow-proxy`.
#[cfg(feature = "shadow-tls")]
pub mod shadow_tls;

/// restls client transport — a record-level TLS client whose session_id
/// authenticates the restls relay; post-handshake data rides tagged
/// records shaped by the record script.  Used by the `restls`
/// Shadowsocks plugin in `meow-proxy`.
#[cfg(feature = "restls")]
pub mod restls;

/// jls client transport — a record-level TLS 1.3 client whose
/// ClientHello/ServerHello `random` fields carry sealed credential blobs;
/// post-handshake data is plain TLS application records.  Used by the
/// `jls` Shadowsocks plugin in meow-proxy. Built on `restls`'s shared
/// tls13 driver.
#[cfg(feature = "jls")]
pub mod jls;

/// SIP004 simple-obfs HTTP/TLS obfuscation codec (client +, later, server).
/// Gated by the `simple-obfs` feature; see [`simple_obfs::client`] for the
/// outbound (proxy-client) wrappers used by the SS / Snell adapters.
#[cfg(feature = "simple-obfs")]
pub mod simple_obfs;

/// kcptun SS-plugin transport (issue #533): a kcp-go wire-compatible
/// KCP-over-UDP stream plus the crypt/FEC/snappy packet layers.
/// Gated by the `kcptun` feature; the smux session and client pool live
/// in `meow-proxy`.
#[cfg(feature = "kcptun")]
pub mod kcptun;

/// A duplex byte stream — the currency passed between transport layers.
///
/// Blanket-implemented for every `T: AsyncRead + AsyncWrite + Unpin + Send + Sync`,
/// so `TcpStream`, `TlsStream<…>`, `WebSocketStream<…>`, etc. all qualify.
///
/// `Sync` is required (in addition to ADR-0001's `Send`) so that a
/// `Box<dyn Stream>` can satisfy `ProxyConn` in `meow-proxy`, which
/// requires `Sync` for connection-table access.  All concrete stream types
/// we use (`TcpStream`, `TlsStream`, `WsStream`) are `Sync`; the bound
/// adds no real restriction in practice.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any> Stream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Whether `stream` can later switch to raw passthrough — a REALITY or
/// BoringSSL TLS stream from [`tls::TlsLayer`], not wrapped by any other
/// layer.  Side-effect free; XTLS-Vision uses it to pick its final
/// uplink padding command before committing to a switch.
pub fn supports_raw_passthrough(stream: &mut dyn Stream) -> bool {
    #[cfg(feature = "tls")]
    {
        let any = stream.as_any_mut();
        #[cfg(feature = "reality")]
        {
            if any.is::<reality_tls::RealityTlsStream>() {
                return true;
            }
        }
        if any.is::<tls::boring_stream::BoringTlsStream>() {
            return true;
        }
    }

    let _ = stream;
    false
}

pub fn enable_raw_passthrough(stream: &mut dyn Stream) -> bool {
    let read = enable_raw_read_passthrough(stream);
    let write = enable_raw_write_passthrough(stream);
    read || write
}

/// Switch a TLS stream's reads, one-way, to the raw transport under it
/// (XTLS-Vision DIRECT).  Plaintext already decrypted from the current
/// record is returned first.  `false` if the stream cannot switch (see
/// [`supports_raw_passthrough`]) or refuses because bytes past the
/// switch point were already buffered inside TLS.
pub fn enable_raw_read_passthrough(stream: &mut dyn Stream) -> bool {
    #[cfg(feature = "tls")]
    {
        let any = stream.as_any_mut();
        #[cfg(feature = "reality")]
        {
            if let Some(reality) = any.downcast_mut::<reality_tls::RealityTlsStream>() {
                reality.enable_raw_read_passthrough();
                return true;
            }
        }
        if let Some(boring) = any.downcast_mut::<tls::boring_stream::BoringTlsStream>() {
            return boring.enable_raw_read_passthrough();
        }
    }

    let _ = stream;
    false
}

/// Switch a TLS stream's writes, one-way, to the raw transport under it
/// (XTLS-Vision DIRECT); shutdown then closes the transport without a
/// TLS close_notify.  Call only after every TLS write has completed.
/// `false` if the stream cannot switch or a TLS record is still pending.
pub fn enable_raw_write_passthrough(stream: &mut dyn Stream) -> bool {
    #[cfg(feature = "tls")]
    {
        let any = stream.as_any_mut();
        #[cfg(feature = "reality")]
        {
            if let Some(reality) = any.downcast_mut::<reality_tls::RealityTlsStream>() {
                reality.enable_raw_write_passthrough();
                return true;
            }
        }
        if let Some(boring) = any.downcast_mut::<tls::boring_stream::BoringTlsStream>() {
            return boring.enable_raw_write_passthrough();
        }
    }

    let _ = stream;
    false
}

/// A transport layer that wraps an inner [`Stream`] and produces a new one.
///
/// Implementations are cheap to clone (typically an `Arc<Config>` inside).
/// The trait is object-safe: `Box<dyn Transport>` is valid.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Wrap `inner` with this transport layer and return the upgraded stream.
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>>;
}

/// Crate-level `Result` alias.  Errors are always [`TransportError`].
pub type Result<T> = std::result::Result<T, TransportError>;
