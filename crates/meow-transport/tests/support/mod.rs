//! Shared test helpers for `meow-transport` integration tests.
//!
//! Contains server-side code (TcpListener, TlsAcceptor, etc.) that is
//! explicitly forbidden inside `src/` by acceptance criterion #8.
//! Tests/support is whitelisted from the F2 grep-check.

#[cfg(any(feature = "grpc", feature = "h2", feature = "xhttp"))]
pub mod h2_push;
#[cfg(any(feature = "grpc", feature = "h2"))]
pub mod h2_stalled;
pub mod log_capture;
pub mod loopback;
