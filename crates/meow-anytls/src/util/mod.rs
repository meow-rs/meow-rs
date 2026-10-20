pub mod auth;
/// Certificate analysis and information extraction (server side)
#[cfg(feature = "server")]
pub mod cert_analyzer;
/// Certificate reloader with hot reload support (server side)
#[cfg(feature = "server")]
pub mod cert_reloader;
pub mod dns_cache;
/// Error types and Result alias
pub mod error;
pub mod net;
/// Android `VpnService.protect(fd)` integration hook for outbound sockets.
pub mod socket_protect;
/// String-based key-value map implementation
pub mod string_map;
pub mod tls;

pub use auth::*;
#[cfg(feature = "server")]
pub use cert_analyzer::*;
#[cfg(feature = "server")]
pub use cert_reloader::*;
pub use dns_cache::*;
pub use error::*;
pub use net::*;
#[cfg(any(target_os = "android", target_env = "ohos"))]
pub use socket_protect::{
    SocketProtector, clear_socket_protector, set_socket_protector, socket_protector,
};
pub use socket_protect::{
    TcpDialer, bind_udp, clear_tcp_dialer, connect_tcp, connect_tcp_addr, set_tcp_dialer,
    tcp_dialer,
};
pub use string_map::*;
pub use tls::*;
