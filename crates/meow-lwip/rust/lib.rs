#![doc = include_str!("../README.md")]

mod core;
mod lwip;
mod stack;
mod tcp_listener;
mod tcp_stream;
mod udp;
mod util;

pub use stack::NetStack;
pub use tcp_listener::TcpListener;
pub use tcp_stream::TcpStream;
pub use {udp::RecvHalf as UdpRecvHalf, udp::SendHalf as UdpSendHalf, udp::UdpPkt, udp::UdpSocket};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("LwIP error ({0})")]
    LwIP(i8),
    #[error("MTU {0} is below the IPv6 minimum 1280")]
    InvalidMtu(u16),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
