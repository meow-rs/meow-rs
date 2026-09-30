//! sing-mux compatible connection multiplexing (mihomo-style).
//!
//! Implements the client side of the protocol used by mihomo / sing-box:
//! a single physical proxy connection carries a mux session, and each
//! logical flow is one mux stream.  Wire format mirrors metacubex/sing-mux:
//!
//! * reserved destination `sp.mux.sing-box.arpa:444` in the proxy
//!   handshake marks the connection as a mux connection (server side);
//! * after the proxy handshake the client sends a 2-byte (+padding) request
//!   header picking the mux protocol (smux / yamux / h2mux); with padding
//!   enabled the session then runs over a `padding::PaddingConn`;
//! * every stream carries the real destination as a sing-encoded
//!   `Socksaddr` prefix (see `address`).
//!
//! See docs/specs/proxy-mux.md for the full wire specification.

pub mod address;
pub mod client;
pub mod h2mux;
pub mod muxcool;
pub mod packet;
pub mod padding;
pub mod request;
pub mod smux;
pub mod stream;
pub mod yamux;

pub use client::{DialFn, MuxClient, MuxOptions};
pub use packet::MuxPacketConn;
pub use stream::MuxStreamConn;

/// Reserved destination used in the proxy handshake to open a mux session.
pub const MUX_DESTINATION_FQDN: &str = "sp.mux.sing-box.arpa";
pub const MUX_DESTINATION_PORT: u16 = 444;

/// Mux protocol identifiers.
///
/// `Smux`/`Yamux`/`H2Mux` match sing-mux's request-header byte values.
/// `MuxCool` is Xray's frame mux: it has **no** request-header byte — the
/// VLESS `CommandMux` request (cmd 0x03) written by the session dialer is
/// the signaling, and the value 3 is only a config-side discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Smux = 0,
    Yamux = 1,
    H2Mux = 2,
    MuxCool = 3,
}

impl Protocol {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "" | "h2mux" => Some(Protocol::H2Mux),
            "smux" => Some(Protocol::Smux),
            "yamux" => Some(Protocol::Yamux),
            // VLESS-only: speaks Xray's Mux.Cool frames (CommandMux=0x03).
            "muxcool" => Some(Protocol::MuxCool),
            _ => None,
        }
    }
}
