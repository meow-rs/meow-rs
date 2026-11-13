// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod rate_limiter;

mod session;
mod timers;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

use std::collections::VecDeque;
// PATCH(lint): `use std::convert::{TryFrom, TryInto}` removed — both are in
// the edition-2021 prelude and the explicit import is a redundant-import
// warning on the workspace toolchain.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
// `pub` (not upstream's private `const`) so the pump can size its work
// buffer against the same constant instead of a magic 32 (PATCH(13)).
pub const DATA_OVERHEAD_SZ: usize = 32;

// PATCH(17): `pub` — the payload offset inside a DATA datagram
// (4-byte type+reserved, 4-byte receiver index, 8-byte counter).
// `parse_incoming_packet` slices `encrypted_encapsulated_packet` from
// here, and `decapsulate_in_place` opens the ciphertext at this offset
// *inside the datagram itself*, so callers slicing the plaintext out of
// the same buffer start here too.
pub const DATA_PAYLOAD_OFF: usize = 16;

// PATCH(lint): Copy derived on the four packet-view structs — all fields are
// Copy and upstream passes them by value without consuming them
// (needless_pass_by_value). No behavior change.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

impl PacketData<'_> {
    /// PATCH(18): the transport counter — the AEAD nonce for the
    /// in-place open and the replay-window key. The in-crate paths read
    /// the field directly; the accessor exists for the crypto-pool
    /// consumers (the meow-proxy pump, the meow-listener demux) when
    /// they build a `CryptoJob` out of an owned datagram.
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// Describes a packet from network
#[derive(Debug, Clone, Copy)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

/// PATCH(18): a shared handle to one session's crypto state — an `Arc`
/// clone of the `SessionCrypto` the session ring itself owns. A worker
/// pass opens data packets through it without borrowing `Tunn`, and a
/// packet whose session rotated out of the ring mid-batch still
/// decrypts through the handle it captured.
#[derive(Clone)]
pub struct SessionHandle(pub(crate) Arc<session::SessionCrypto>);

impl SessionHandle {
    /// The in-place open the crypto pool runs — identical to the call
    /// `handle_data_in_place` makes on the ring slot's `Session`,
    /// exposed on the shared crypto so `&mut Tunn` is not required.
    pub(crate) fn open_in_place(
        &self,
        receiver_idx: u32,
        counter: u64,
        ct_and_tag: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        self.0
            .receive_packet_data_in_place(receiver_idx, counter, ct_and_tag)
    }
}

/// PATCH(18): the verify/demux verdict `decapsulate*` used to compute
/// inline — split out of `classify_incoming` so a batch drain can park
/// the DATA arm on the crypto pool and resume its bookkeeping at
/// [`Tunn::handle_decrypted_data`]. `Packet` itself stays the carrier
/// for every other type: callers feed `Other` back into
/// `handle_verified_packet` unchanged.
#[derive(Debug)]
pub enum WireClass<'a> {
    /// A verified DATA packet — the caller owns the datagram (the
    /// worker opens `buf[DATA_PAYLOAD_OFF..]` in place), so only the
    /// parsed view travels here.
    Data(PacketData<'a>),
    /// Any other verified packet — handshake, cookie reply — handled
    /// serially through `handle_verified_packet` exactly as
    /// `decapsulate` dispatches it.
    Other(Packet<'a>),
    /// An under-load cookie reply the limiter already rendered into
    /// `dst[..len]` — send it, then run the chained empty-datagram
    /// flush.
    CookieReply(usize),
    /// mac1/format verification failed — drop, silent by contract.
    Drop(WireGuardError),
}

impl Tunn {
    #[inline(always)]
    // PATCH(lint): `Packet<'_>` spelled out — rustc's
    // mismatched_lifetime_syntaxes lint rejects hiding it.
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet<'_>, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=std::usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[DATA_PAYLOAD_OFF..],
            }),
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);

        Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index << 8,
                preshared_key,
            ),
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none()),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),
        }
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // Send the packet using an established session
            let packet = session.format_packet_data(src, dst);
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            return TunnResult::WriteToNetwork(packet);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// PATCH(18): `decapsulate*`'s verify/dispatch half, split out so a
    /// batch drain can run this serially per datagram and park the DATA
    /// arm on the crypto pool — the pool only ever sees a `WireClass`,
    /// never `&mut Tunn`. `dst` is the same crypto scratch contract as
    /// `decapsulate`: a `CookieReply` verdict is already rendered into
    /// `dst[..len]` for the caller to send (then run the chained flush).
    ///
    /// `datagram` must have its reserved bytes 1..4 handled by the
    /// caller exactly as for `decapsulate` — this function performs the
    /// identical `verify_packet` + dispatch the fused calls did, in the
    /// identical order.
    pub fn classify_incoming<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &'a [u8],
        dst: &mut [u8],
    ) -> WireClass<'a> {
        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .verify_packet(src_addr, datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return WireClass::CookieReply(cookie.len());
            }
            Err(TunnResult::Err(e)) => return WireClass::Drop(e),
            _ => unreachable!(),
        };
        match packet {
            Packet::PacketData(p) => WireClass::Data(p),
            other => WireClass::Other(other),
        }
    }

    /// PATCH(18): an `Arc` clone of the crypto state for the session
    /// `receiver_idx` demuxes to — the handle a `CryptoJob` opens the
    /// packet through, so a worker never touches `self.sessions`. The
    /// ring slot itself stays put; `None` when no session holds that
    /// index (the job then reports `NoCurrentSession`, same verdict
    /// `handle_data*` gives).
    pub fn session_handle_for(&self, receiver_idx: u32) -> Option<SessionHandle> {
        self.sessions[receiver_idx as usize % N_SESSIONS]
            .as_ref()
            .map(|s| SessionHandle(Arc::clone(&s.crypto)))
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        match self.classify_incoming(src_addr, datagram, dst) {
            WireClass::Data(p) => self.handle_verified_packet(Packet::PacketData(p), dst),
            WireClass::Other(packet) => self.handle_verified_packet(packet, dst),
            WireClass::CookieReply(len) => TunnResult::WriteToNetwork(&mut dst[..len]),
            WireClass::Drop(e) => TunnResult::Err(e),
        }
    }

    /// PATCH(17): `decapsulate`'s in-place twin for the single-peer data
    /// path. `datagram` is the caller-owned receive buffer holding one
    /// wire datagram; a DATA packet's ciphertext at
    /// `datagram[DATA_PAYLOAD_OFF..]` is opened *where it stands* — the
    /// plaintext occupies the same range — so a `WriteToTunnelV4/V6`
    /// result hands back a subslice of `datagram` itself and the caller
    /// moves the whole buffer onward with no decrypt-into-scratch copy.
    /// Everything else — handshake/cookie dispatch, the cookie reply
    /// under load, the chained empty-datagram flush — behaves exactly
    /// like `decapsulate` and writes into `dst` (which may alias nothing
    /// in `datagram`; the caller passes its crypto scratch).
    ///
    /// Like `decapsulate`, a `WriteToNetwork` result asks for another
    /// call with an empty datagram until it stops producing output.
    pub fn decapsulate_in_place<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &'a mut [u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        // `WireClass::Data`'s `PacketData` borrows `datagram`, so the
        // in-place arm first drops that borrow: the dispatch fields are
        // Copy, they come out of the view here, and the `&mut` the
        // decrypt needs is only created after `p` is dead. Non-data
        // packets keep `packet` alive into `handle_verified_packet` —
        // exactly like `decapsulate`.
        match self.classify_incoming(src_addr, datagram, dst) {
            WireClass::Data(p) => self
                .handle_data_in_place(
                    p.receiver_idx,
                    p.counter,
                    p.encrypted_encapsulated_packet.len(),
                    datagram,
                )
                .unwrap_or_else(TunnResult::from),
            WireClass::Other(packet) => self.handle_verified_packet(packet, dst),
            WireClass::CookieReply(len) => TunnResult::WriteToNetwork(&mut dst[..len]),
            WireClass::Drop(e) => TunnResult::Err(e),
        }
    }

    // PATCH(15): pub(crate) -> pub — a responder-style caller (the WG
    // inbound listener) needs the upstream device-order split of
    // `decapsulate`: rate-limit + mac1 verify first, dispatch by peer, then
    // this call, so a forged init pays no DH/AEAD before the limiter and a
    // known init pays the handshake crypto exactly once.
    pub fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p),
            Packet::PacketData(p) => self.handle_data(p, dst),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_initiation",
            remote_idx = p.sender_idx
        );

        let (packet, session) = self.handshake.receive_handshake_initialization(p, dst)?;

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(TunnResult::WriteToNetwork(packet))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_handshake_response(p)?;

        let keepalive_packet = session.format_packet_data(&[], dst);
        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received cookie_reply",
            local_idx = p.receiver_idx
        );

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        tracing::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS]
                >= self.timers.session_timers[cur_idx % N_SESSIONS]
        {
            self.current = new_idx;
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// PATCH(17): `handle_data`'s in-place twin — same session lookup,
    /// counter bookkeeping and decapsulated-packet validation, but the
    /// ciphertext already sits at `buf[DATA_PAYLOAD_OFF..DATA_PAYLOAD_OFF
    /// + ct_len]` inside the receive buffer, so the plaintext is
    /// produced there and the result borrows `buf`, not a `dst`.
    fn handle_data_in_place<'a>(
        &mut self,
        receiver_idx: u32,
        counter: u64,
        ct_len: usize,
        buf: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let pt_len = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data_in_place(
                receiver_idx,
                counter,
                &mut buf[DATA_PAYLOAD_OFF..DATA_PAYLOAD_OFF + ct_len],
            )?
        };

        Ok(self.handle_decrypted_data(receiver_idx, pt_len, buf))
    }

    /// PATCH(18): `handle_data_in_place`'s serial tail, split at the
    /// AEAD open so the crypto pool can run the open itself off-actor.
    /// `buf` is the wire datagram whose `buf[DATA_PAYLOAD_OFF..]`
    /// region a decrypt pass just rewrote into `pt_len` plaintext
    /// bytes. Runs the identical `set_current_session` → timer →
    /// validate sequence the fused path did — the batch drain calls it
    /// in the caller's arrival order, so session/timer/byte bookkeeping
    /// is indistinguishable from serial processing.
    ///
    /// Trust contract: `pt_len` must be a result the pool's
    /// `open_in_place` produced on this same `buf` — then
    /// `pt_len <= buf.len() - DATA_PAYLOAD_OFF` holds by construction.
    /// Feed it nothing else; the plaintext slice below is indexed, not
    /// bounds-checked against the wire datagram.
    pub fn handle_decrypted_data<'a>(
        &mut self,
        receiver_idx: u32,
        pt_len: usize,
        buf: &'a mut [u8],
    ) -> TunnResult<'a> {
        let r_idx = receiver_idx as usize;

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        self.validate_decapsulated_packet(&mut buf[DATA_PAYLOAD_OFF..DATA_PAYLOAD_OFF + pt_len])
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        match self.handshake.format_handshake_initiation(dst) {
            Ok(packet) => {
                tracing::debug!("Sending handshake_initiation");

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                TunnResult::WriteToNetwork(packet)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

    use super::*;
    use rand_core::{OsRng, RngCore};

    /// PATCH(14): serializes tests that advance the process-global mock
    /// clock — or whose asserts depend on a clock-sensitive intermediate
    /// state. Otherwise one test's `MockClock::advance` can land inside a
    /// sibling's in-flight `InitSent` window and push it past
    /// REKEY_ATTEMPT_TIME: `new_handshake_after_two_mins`'s +120s made
    /// `handshake_no_resp_rekey_timeout` fail intermittently under
    /// `cargo test` (cargo-nextest's per-test processes cannot collide).
    static TIMER_CLOCK_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn create_two_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new(my_secret_key, their_public_key, None, None, my_idx, None);

        let their_tun = Tunn::new(their_secret_key, my_public_key, None, None, their_idx, None);

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        // PATCH(lint): manual_let_else — mechanical rewrites, same behavior
        let TunnResult::WriteToNetwork(handshake_init) = handshake_init else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn create_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        let TunnResult::WriteToNetwork(handshake_resp) = handshake_resp else {
            unreachable!();
        };

        handshake_resp.into()
    }

    fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let TunnResult::WriteToNetwork(keepalive) = keepalive else {
            unreachable!();
        };

        keepalive.into()
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        // PATCH(deps): upstream used etherparse::PacketBuilder (dev-dep we do
        // not vendor). This is the same packet spelled out: IPv4/20B + UDP/8B
        // + 4B payload. The tunnel only inspects the version nibble, the
        // total-length field and the source address.
        Vec::from([
            0x45, 0x00, 0x00, 0x20, // v4+ihl5, dscp=0, total_len=32
            0x00, 0x00, 0x00, 0x00, // id, flags+fragment offset
            0x05, 0x11, 0x00, 0x00, // ttl=5, proto=UDP(17), checksum=0 (unchecked here)
            192, 168, 1, 2, // src
            192, 168, 1, 3, // dst
            0x16, 0x2e, 0x00, 0x17, // udp src=5678, dst=23
            0x00, 0x0c, 0x00, 0x00, // udp len=12, checksum=0
            0x00, 0x01, 0x02, 0x03, // payload
        ])
    }

    #[cfg(feature = "mock-instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let mut dst = vec![0u8; 2048];
        let result = tun.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        let TunnResult::WriteToNetwork(packet_data) = result else {
            unreachable!();
        };
        let packet = Tunn::parse_incoming_packet(packet_data).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let packet = Tunn::parse_incoming_packet(&resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        let packet = Tunn::parse_incoming_packet(&keepalive).unwrap();
        assert!(matches!(packet, Packet::PacketData(_)));
    }

    #[test]
    fn full_handshake_plus_timers() {
        // Asserts on a clock-sensitive intermediate state (`Done` holds
        // only while no timer has fired): hold the lock so a sibling's
        // `MockClock::advance` cannot land mid-test.
        let _clock = TIMER_CLOCK_LOCK.lock();
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn new_handshake_after_two_mins() {
        let _clock = TIMER_CLOCK_LOCK.lock();
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        crate::mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let sent_packet_buf = create_ipv4_udp_packet();
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));

        //Advance to timeout
        crate::mock_instant::MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_no_resp_rekey_timeout() {
        let _clock = TIMER_CLOCK_LOCK.lock();
        let (mut my_tun, _their_tun) = create_two_tuns();

        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));

        crate::mock_instant::MockClock::advance(REKEY_TIMEOUT);
        update_timer_results_in_handshake(&mut my_tun);
    }

    /// A `HandshakeState::Expired` session is recoverable: once the
    /// handshake is `Expired`, `update_timers` reports
    /// `Err(ConnectionExpired)` on every tick — the sticky error a caller
    /// that swallows it would see forever — until boringtun's own
    /// recovery, `format_handshake_initiation(dst, true)` (the same call
    /// `update_timers` itself makes on a rekey timeout), moves the
    /// handshake back to `InitSent`. The meow-proxy wireguard pump's
    /// `tick_timers` relies on exactly this contract.
    ///
    /// `set_expired()` plants the same terminal state the
    /// REKEY_ATTEMPT_TIME / REJECT_AFTER_TIME*3 paths produce, without
    /// advancing the process-global mock clock — a real 90s+ advance
    /// would race sibling tests' in-flight handshakes.
    #[test]
    fn forced_handshake_initiation_recovers_expired_session() {
        // The final `update_timers` assert is clock-sensitive: a stray
        // sibling advance could push the fresh InitSent over
        // REKEY_ATTEMPT_TIME and back into `Err`. The lock rules it out.
        let _clock = TIMER_CLOCK_LOCK.lock();
        let (mut my_tun, _their_tun) = create_two_tuns();
        // InitSent with no response — the initiation retry clock runs.
        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));

        // The state every expiry path lands in; the sticky error is what
        // a pump that dropped the `Err` would see on each tick.
        my_tun.handshake.set_expired();
        let mut dst = [0u8; 2048];
        assert!(matches!(
            my_tun.update_timers(&mut dst),
            TunnResult::Err(WireGuardError::ConnectionExpired)
        ));
        assert!(matches!(
            my_tun.update_timers(&mut dst),
            TunnResult::Err(WireGuardError::ConnectionExpired)
        ));
        assert!(my_tun.is_expired());

        // The forced resend emits a fresh initiation and un-expires the
        // handshake — no clock involvement, fully deterministic.
        let res = my_tun.format_handshake_initiation(&mut dst, true);
        assert!(matches!(res, TunnResult::WriteToNetwork(_)));
        let TunnResult::WriteToNetwork(packet_data) = res else {
            unreachable!();
        };
        let packet = Tunn::parse_incoming_packet(packet_data).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
        assert!(!my_tun.is_expired());

        // The tick is off the sticky-error path and back to normal duty:
        // an idle tick has nothing to do — a deterministic `Done` under
        // the clock lock.
        let res = my_tun.update_timers(&mut dst);
        assert!(matches!(res, TunnResult::Done), "got {res:?}");
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let TunnResult::WriteToNetwork(data) = data else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let TunnResult::WriteToTunnelV4(recv_packet_buf, _addr) = data else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    /// PATCH(18): the crypto-pool consumers' recipe — classify on the
    /// actor, open on the pool, post-pass in order. Sealed datagrams for
    /// `their_tun`'s receive session, built in wire order, then run
    /// through the pool in a deliberately interleaved job order: every
    /// job still decrypts (replay marks are counter-keyed, not
    /// order-keyed) and the job list itself stays in submission order —
    /// which is what the pump's serial post-pass replays.
    #[test]
    fn parallel_rx_order_preserved() {
        use crate::crypto_pool::{CryptoJob, CryptoPool};

        let (mut my_tun, their_tun) = create_two_tuns_and_handshake();
        let mut enc_dst = [0u8; 2048];
        let base = create_ipv4_udp_packet();
        // 64 wire datagrams under consecutive counters, each carrying a
        // distinct last payload byte.
        let mut wires = Vec::new();
        let mut inners = Vec::new();
        for i in 0u8..64 {
            let mut inner = base.clone();
            *inner.last_mut().unwrap() = i;
            let TunnResult::WriteToNetwork(w) = my_tun.encapsulate(&inner, &mut enc_dst) else {
                unreachable!();
            };
            inners.push(inner);
            wires.push(w.to_vec());
        }
        // Interleaved job order: evens then odds — out-of-counter-order
        // within the batch is the whole point of the worker pass.
        let order: Vec<usize> = (0..64).step_by(2).chain((1..64).step_by(2)).collect();
        let mut jobs: Vec<CryptoJob> = order
            .iter()
            .map(|&i| {
                let wire = wires[i].clone();
                let r_idx = u32::from_le_bytes(wire[4..8].try_into().unwrap());
                let counter = u64::from_le_bytes(wire[8..16].try_into().unwrap());
                CryptoJob::new(
                    wire.clone(),
                    wire.len(),
                    r_idx,
                    counter,
                    their_tun.session_handle_for(r_idx),
                )
            })
            .collect();
        CryptoPool::new(4).run(&mut jobs);
        assert_eq!(jobs.len(), 64);
        for (pos, job) in jobs.iter().enumerate() {
            let i = order[pos];
            let pt_len = match &job.result {
                Some(Ok(len)) => *len,
                other => panic!("job {pos} (packet {i}) failed: {other:?}"),
            };
            assert_eq!(
                &job.buf[DATA_PAYLOAD_OFF..DATA_PAYLOAD_OFF + pt_len],
                &inners[i][..],
                "job {pos} (packet {i}) plaintext"
            );
        }
        // Every counter is now marked on the shared session — a replay
        // of the first packet must fail through the same handle.
        let wire = wires[0].clone();
        let r_idx = u32::from_le_bytes(wire[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(wire[8..16].try_into().unwrap());
        let mut dup = vec![CryptoJob::new(
            wire.clone(),
            wire.len(),
            r_idx,
            counter,
            their_tun.session_handle_for(r_idx),
        )];
        CryptoPool::new(4).run(&mut dup);
        assert!(matches!(
            dup[0].result,
            Some(Err(WireGuardError::DuplicateCounter))
        ));
    }

    /// PATCH(18): the replay-window mutex under real contention — the
    /// same wire datagram four times in one batch must open exactly
    /// once: every worker passes the quick check before the winner's
    /// mark lands, so the losers die on the authoritative mark.
    #[test]
    fn parallel_rx_replay_rejection() {
        use crate::crypto_pool::{CryptoJob, CryptoPool};

        let (mut my_tun, their_tun) = create_two_tuns_and_handshake();
        let mut enc_dst = [0u8; 2048];
        let inner = create_ipv4_udp_packet();
        let TunnResult::WriteToNetwork(w) = my_tun.encapsulate(&inner, &mut enc_dst) else {
            unreachable!();
        };
        let wire = w.to_vec();
        let r_idx = u32::from_le_bytes(wire[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(wire[8..16].try_into().unwrap());
        let mut jobs: Vec<CryptoJob> = (0..4)
            .map(|_| {
                CryptoJob::new(
                    wire.clone(),
                    wire.len(),
                    r_idx,
                    counter,
                    their_tun.session_handle_for(r_idx),
                )
            })
            .collect();
        CryptoPool::new(4).run(&mut jobs);
        let ok = jobs
            .iter()
            .filter(|j| matches!(j.result, Some(Ok(_))))
            .count();
        let dup = jobs
            .iter()
            .filter(|j| {
                matches!(
                    j.result,
                    Some(Err(
                        WireGuardError::DuplicateCounter | WireGuardError::InvalidCounter
                    ))
                )
            })
            .count();
        assert_eq!(ok, 1, "exactly one duplicate may open");
        assert_eq!(dup, 3, "the other three must be replay-rejected");
    }

    /// PATCH(18): a session handle outlives its ring slot — the
    /// `Arc<SessionCrypto>` contract that makes a batch safe when a
    /// re-handshake lands mid-pass. Session indices cycle the low byte
    /// (`handshake.inc_index`), so eight fresh responder sessions wrap
    /// the newest generation back onto the captured slot: the ring no
    /// longer resolves the old wire packet (`WrongIndex`), yet the
    /// handle taken before the rotation still decrypts it.
    #[test]
    fn parallel_rx_session_rotation_mid_batch() {
        use crate::crypto_pool::{CryptoJob, CryptoPool};

        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut enc_dst = [0u8; 2048];

        // Three datagrams sealed under the *current* session
        // generation — `n > 2` is what pushes each pool pass below onto
        // real worker threads instead of the inline shortcut. Distinct
        // last payload bytes keep the plaintexts checkable per job.
        let base = create_ipv4_udp_packet();
        let mut old_wires = Vec::new();
        let mut inners = Vec::new();
        for i in 0u8..3 {
            let mut inner = base.clone();
            *inner.last_mut().unwrap() = i;
            let TunnResult::WriteToNetwork(w) = my_tun.encapsulate(&inner, &mut enc_dst) else {
                unreachable!();
            };
            inners.push(inner);
            old_wires.push(w.to_vec());
        }
        let r_idx = u32::from_le_bytes(old_wires[0][4..8].try_into().unwrap());
        let old_handle = their_tun
            .session_handle_for(r_idx)
            .expect("session established");

        // Rotate the slot: every handled initiation stores a new
        // responder session whose local index is one higher in the low
        // byte — eight generations wrap back onto `r_idx % N_SESSIONS`.
        // Under `mock-instant` the clock is frozen, so advance between
        // handshakes or the responder's tai64n monotonicity check
        // rejects every init after the first (the lock serializes the
        // process-global offset).
        let _clock = TIMER_CLOCK_LOCK.lock();
        for _ in 0..8 {
            #[cfg(feature = "mock-instant")]
            crate::mock_instant::MockClock::advance(Duration::from_millis(10));
            let init = create_handshake_init(&mut my_tun);
            let resp = create_handshake_response(&mut their_tun, &init);
            let keepalive = parse_handshake_resp(&mut my_tun, &resp);
            parse_keepalive(&mut their_tun, &keepalive);
        }
        drop(_clock);

        // The slot now holds a new generation — the same `r_idx` lookup
        // returns crypto that rejects every old wire packet as
        // `WrongIndex`, on the pool's parallel arm.
        let mut stale: Vec<CryptoJob> = old_wires
            .iter()
            .map(|wire| {
                CryptoJob::new(
                    wire.clone(),
                    wire.len(),
                    r_idx,
                    u64::from_le_bytes(wire[8..16].try_into().unwrap()),
                    their_tun.session_handle_for(r_idx),
                )
            })
            .collect();
        CryptoPool::new(4).run(&mut stale);
        assert_eq!(stale.len(), 3);
        for (i, job) in stale.iter().enumerate() {
            assert!(
                matches!(job.result, Some(Err(WireGuardError::WrongIndex))),
                "post-rotation session must reject old wire packet {i}, got {:?}",
                job.result
            );
        }

        // But the captured handle IS the old session's crypto — the
        // `Arc` keeps it alive past ring eviction, and it still opens
        // every datagram the stale lookup rejected (distinct counters,
        // so the shared replay window admits all three).
        let mut jobs: Vec<CryptoJob> = old_wires
            .iter()
            .map(|wire| {
                CryptoJob::new(
                    wire.clone(),
                    wire.len(),
                    r_idx,
                    u64::from_le_bytes(wire[8..16].try_into().unwrap()),
                    Some(old_handle.clone()),
                )
            })
            .collect();
        CryptoPool::new(4).run(&mut jobs);
        assert_eq!(jobs.len(), 3);
        for (i, job) in jobs.iter().enumerate() {
            let pt_len = match job.result {
                Some(Ok(len)) => len,
                ref other => panic!("old handle must still decrypt job {i}: {other:?}"),
            };
            assert_eq!(
                &job.buf[DATA_PAYLOAD_OFF..DATA_PAYLOAD_OFF + pt_len],
                &inners[i][..]
            );
        }
    }
}
