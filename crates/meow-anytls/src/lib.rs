//! AnyTLS protocol implementation in Rust
//!
//! A proxy protocol attempting to mitigate TLS in TLS fingerprinting issues.
//!
//! # Architecture
//!
//! - **protocol**: Frame and codec implementation
//! - **session**: Session and stream management
//! - **padding**: Traffic obfuscation padding
//! - **util**: Utilities (error handling, auth, the `TlsConnect` hook)
//! - **client**: Client implementation — TLS is supplied by the host via
//!   [`util::tls::TlsConnect`], so the client links no TLS library itself
//! - **server**: Server implementation (feature `server`, rustls-based)

/// Client implementation
pub mod client;
/// Padding module for traffic obfuscation
pub mod padding;
/// Protocol layer: Frame and codec implementation
pub mod protocol;
/// Server implementation (feature `server`; rustls-based)
#[cfg(feature = "server")]
pub mod server;
/// Session layer: Session and stream management
pub mod session;
/// Wire helpers: SOCKS destination parse and the UoT v2 codec shared by
/// the dev `server` fixture and the production inbound listener.
pub mod uot;
/// Utility modules (error, auth, TLS, etc.)
pub mod util;

pub use client::*;
pub use padding::*;
pub use protocol::*;
pub use session::*;
pub use util::*;

// Re-export commonly used types
pub use util::auth::{
    UserMap, authenticate_client, authenticate_user, hash_password, send_authentication,
};
pub use util::error::{AnyTlsError, Result};
