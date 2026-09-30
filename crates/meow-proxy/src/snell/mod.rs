//! Snell v3 / v4 / v5 / v6 outbound proxy adapter.
//!
//! The v3–v5 client side is a port of
//! [opensnell](https://github.com/missuo/opensnell); v6 adds its own record
//! layer:
//!
//! * [`cipher`] — Argon2id KDF + AES-128-GCM helpers.
//! * [`v3`]    — Shadowsocks-AEAD-compatible Snell v3 codec.
//! * [`v4`]    — AEAD frame codec (`v4Conn`) with padding interleave and
//!   payload-limit ramp-up.
//! * [`v6`]    — v6 record layer (`default` / `unshaped` / `unsafe-raw`
//!   framing); `v6_shape` derives the `default`-mode traffic shaping.
//! * [`protocol`] — `Snell` stream wrapper with request/response handling.
//! * [`udp`]   — UDP-over-TCP datagram framing exposed as `ProxyPacketConn`.
//! * [`pool`]  — bounded LIFO reuse pool for `CommandConnectV2` sessions.
//! * [`adapter`] — `SnellAdapter` implementing [`meow_common::ProxyAdapter`].
//!
//! Older snell v1 / v2 wires are intentionally unsupported.

pub mod adapter;
pub mod cipher;
pub mod pool;
pub mod protocol;
pub mod udp;
pub mod v3;
pub mod v4;
pub mod v6;
mod v6_shape;

pub use adapter::{SnellAdapter, SnellObfs, SnellVersion};
pub use v6::SnellV6Mode;
