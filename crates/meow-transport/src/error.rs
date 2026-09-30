/// All errors produced by `meow-transport` layers.
///
/// `#[non_exhaustive]` ensures that adding new variants in future minor
/// versions is not a breaking change for downstream matchers.
///
/// Adapters (`meow-proxy`) convert this via the `transport_to_proxy_err`
/// map_err helper — or the identical `Io`-arm-preserving match inline
/// where a per-site context string is needed — in `meow-proxy` (not a
/// `From` impl here: the orphan rule keeps `From` impls next to the
/// local type, and the conversion must preserve `Io` verbatim rather
/// than stringify; see `meow-proxy/src/lib.rs`), keeping the crate
/// boundary clean.  No `anyhow::Error` is ever returned from a public
/// function in this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls handshake: {0}")]
    Tls(String),

    #[error("websocket handshake: {0}")]
    WebSocket(String),

    #[error("grpc framing: {0}")]
    Grpc(String),

    #[error("h2: {0}")]
    H2(String),

    #[error("http upgrade: {0}")]
    HttpUpgrade(String),

    #[error("xhttp: {0}")]
    Xhttp(String),

    #[error("invalid config: {0}")]
    Config(String),
}
