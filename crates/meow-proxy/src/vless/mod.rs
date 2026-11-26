//! VLESS protocol sub-modules.
//!
//! Public surface used by [`crate::vless::VlessAdapter`]:
//! - [`header`] — request/response header encoding
//! - [`conn`] — `VlessConn` (TCP) and `VlessPacketConn` (UDP-over-TCP)
//! - [`vision`] — `VisionConn` XTLS-Vision splice wrapper (behind `vless-vision` feature)
//! - [`encryption`] — VLESS post-quantum Encryption (`mlkem768x25519plus`, behind `vless-encryption`)

pub(crate) mod conn;
pub(crate) mod golden;
pub(crate) mod header;

#[cfg(feature = "vless-vision")]
pub(crate) mod request;
#[cfg(feature = "vless-vision")]
pub(crate) mod vision;

#[cfg(feature = "vless-encryption")]
pub mod encryption;

pub(crate) use conn::{VlessConn, VlessPacketConn};
pub(crate) use header::{addr_from_metadata, Cmd};

#[cfg(feature = "vless-vision")]
pub(crate) use vision::VisionConn;

/// Narrow inbound protocol surface for the Vision server side: the bounded
/// request decoder, the constant response header, and the server padding
/// codec.  Everything the VLESS listener wave needs — and nothing more.
#[cfg(feature = "vless-vision")]
pub mod inbound {
    pub use super::header::{VlessAddr, RESPONSE_HEADER as VLESS_RESPONSE_HEADER};
    pub use super::request::{
        flow_is_wire_vision, flow_wire_bytes, read_vless_request, VlessRequest,
        VlessRequestCommand, VlessRequestDecoder, VlessRequestError, VlessRequestFeed,
        VLESS_MUX_REQUEST_MAX_LEN, VLESS_TCP_REQUEST_MAX_LEN, XTLS_RPRX_VISION_FLOW,
    };
    pub use super::vision::server::{VisionServerConn, VisionServerMode};
}
