//! Per-peer state for the WireGuard inbound: one vendored-boringtun
//! [`Tunn`] responder session each, plus the endpoint it currently roams
//! to and the inner-source ACL the config validated non-empty.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use meow_wireguard::noise::rate_limiter::RateLimiter;
use meow_wireguard::x25519;
use meow_wireguard::Tunn;
use smol_str::SmolStr;

use super::WgPeerSpec;

/// A static peer of the listener. `endpoint` is learned by roaming —
/// a responder never initiates, so a peer that has never sent an
/// ACL-admitted inner datagram simply has nowhere to send timer output.
pub(super) struct PeerState {
    /// Log/diagnostic label (`peer-<index>` when the config left the
    /// name empty) — diagnostics only, never enters `Metadata`.
    pub label: SmolStr,
    /// The peer's responder half: its `Tunn` was built with
    /// `index = slot`, so the session receiver indices it mints sit in
    /// the `slot << 8` namespace `demux` decodes.
    pub tunn: Tunn,
    /// Source of the peer's latest ACL-admitted inner packet — the
    /// only datagram allowed to move the endpoint (a bare handshake or
    /// keepalive does not; its reply already answers `src` directly).
    /// See [`crate::wireguard::demux`].
    pub endpoint: Option<SocketAddr>,
    /// Inner-source-IP ACL (`allowed_ips`), validated non-empty at
    /// config load. Applied once, at the inner-packet entry point.
    pub allowed_ips: Arc<[ipnet::IpNet]>,
    /// WARP-style 3-byte reserved field stamped onto bytes 1..4 of
    /// every wire datagram headed to this peer (`None` → zeros).
    pub reserved: Option<[u8; 3]>,
    /// Set once the first established session is logged — keeps the
    /// `info!` line a once-per-session event rather than a per-packet
    /// one. Cleared when the session expires so a re-handshake logs.
    pub session_logged: bool,
}

impl PeerState {
    /// Build the responder `Tunn` for one peer. `index` is the peer slot
    /// — `Tunn::new` shifts it into the session-index namespace itself.
    /// `limiter` is the *listener-shared* limiter: the mac1/cookie path
    /// is keyed on the listener's static public key, so one limiter
    /// protects every peer's handshake surface (and one counter
    /// governs the whole socket's under-load state).
    pub fn new(
        cfg: &WgPeerSpec,
        index: u32,
        static_private: &x25519::StaticSecret,
        limiter: Arc<RateLimiter>,
    ) -> Self {
        let label = if cfg.name.is_empty() {
            SmolStr::from(format!("peer-{index}"))
        } else {
            cfg.name.clone()
        };
        Self {
            label,
            tunn: Tunn::new(
                static_private.clone(),
                x25519::PublicKey::from(cfg.public_key),
                cfg.preshared_key,
                None,
                index,
                Some(limiter),
            ),
            endpoint: None,
            allowed_ips: cfg.allowed_ips.clone().into(),
            reserved: cfg.reserved,
            session_logged: false,
        }
    }

    /// Inbound inner-source-IP ACL check — the responder's spoofing
    /// guard. A peer may only source inner packets whose source address
    /// its `allowed_ips` cover; overlapping entries across peers are
    /// fine because demux already fixed which peer the packet came
    /// through.
    pub fn allows_src(&self, src: IpAddr) -> bool {
        self.allowed_ips.iter().any(|net| net.contains(&src))
    }

    /// Stamp this peer's `reserved` bytes onto a wire datagram headed
    /// to it (bytes 1..4 — after the LE message-type byte). Datagrams
    /// shorter than the WG header minimum can't carry the field, but a
    /// well-formed send never is.
    pub fn stamp_reserved(&self, datagram: &mut [u8]) {
        if let Some(reserved) = self.reserved {
            if datagram.len() >= 4 {
                datagram[1..4].copy_from_slice(&reserved);
            }
        }
    }
}
