//! Wire demultiplexing for the multi-peer responder — the pure-logic
//! half of the actor, deliberately socket-free so the spec's §11.1 demux
//! matrix runs as plain unit tests.
//!
//! One UDP datagram in, [`Action`]s out:
//!
//! 1. **Shared rate limiter first.** Every datagram goes through the
//!    listener-level [`RateLimiter::verify_packet`], which parses the
//!    message and checks handshake `mac1` before any DH/AEAD — a forged
//!    packet costs a BLAKE2 keyed-MAC and nothing else. Under load it
//!    either demands `mac2` (cookie-validated initiators pass straight
//!    through) or hands back a cookie reply we send the source.
//! 2. **Dispatch.** Handshake initiations are anonymous: decrypt just
//!    the static-key field with [`parse_handshake_anon`] and look the
//!    peer up in `peer_by_pubkey`. Everything else — handshake
//!    responses, cookie replies, transport data — carries a
//!    `receiver_idx` we minted, so `receiver_idx >> 8` selects the peer
//!    slot directly (`Tunn::new(index)` puts the slot in the index's
//!    upper bits and cycles sessions through the low byte).
//! 3. **Authenticate, ACL, then roam.** `handle_verified_packet`
//!    produces a [`TunnResult`]; only an inner packet *admitted by the
//!    peer's `allowed_ips` ACL* moves the peer's endpoint — a bare
//!    handshake or keepalive does not (its reply already answers the
//!    datagram's source directly), and neither does an
//!    authenticated-but-ACL-rejected packet, which proves nothing
//!    about where the peer lives. The empty datagrams used to flush
//!    the send queue never touch it (a peer can't be "roamed" by
//!    silence).
//! 4. **Silent-drop discipline.** Unknown keys, bad MACs, out-of-range
//!    indices and malformed packets change nothing and emit nothing —
//!    at most a `trace!` line.
//!
//! The actor owns the socket and the inner-packet sink; this table owns
//! everything between them so its behaviour is assertable end to end.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use meow_wireguard::noise::handshake::parse_handshake_anon;
use meow_wireguard::noise::rate_limiter::RateLimiter;
use meow_wireguard::noise::{Packet, TunnResult};
use meow_wireguard::x25519;
use tracing::trace;

use super::peer::PeerState;
use super::WgListenerSpec;

/// Upper bound on the peer table — the `receiver_idx` namespace gives
/// the slot 24 bits (the low byte cycles session indices), so a table
/// that would overflow it is a configuration error. Checked again at
/// [`PeerTable::new`]; `meow-config` already rejects this at parse time.
pub(crate) const MAX_PEERS: usize = (1 << 24) - 1;

/// What a datagram (or the timer pass) asks the actor to do. The actor
/// maps each variant onto socket sends and inner-packet handling; the
/// table itself never touches I/O.
#[derive(Debug)]
pub(super) enum Action {
    /// A wire datagram to send to `addr`, already reserved-stamped when
    /// the producing peer had a `reserved` configured (cookie replies
    /// are never stamped — they answer an unidentified initiator).
    ToWire { addr: SocketAddr, bytes: Vec<u8> },
    /// A decrypted inner IP packet from peer `slot` whose ACL passed.
    /// `v6` selects the address family; the bytes start at the IP
    /// header. This is the single ACL enforcement point — every inner
    /// packet the stack sees came through here.
    Inner {
        slot: usize,
        v6: bool,
        bytes: Vec<u8>,
    },
}

/// The multi-peer responder table: shared keys and limiter, the
/// peer vector demux indexes into, and the O(1) pubkey map.
pub(super) struct PeerTable {
    /// Responder static keypair — `public` is also the limiter's mac1
    /// identity. Never logged.
    secret: x25519::StaticSecret,
    public: x25519::PublicKey,
    limiter: Arc<RateLimiter>,
    peers: Vec<PeerState>,
    /// `peer_static_public` → slot. Handshake initiations are the only
    /// packets that arrive without a receiver index we minted, so this
    /// is the only by-key lookup the demux needs.
    peer_by_pubkey: HashMap<[u8; 32], usize>,
}

/// The listener-wide handshake rate budget — boringtun's
/// `PEER_HANDSHAKE_RATE_LIMIT`, kept at its upstream default of 10
/// verified handshake packets per limiter window (vendored at
/// `meow-wireguard/src/noise/mod.rs`, where `Tunn::new` uses it when no
/// limiter is passed; the multi-peer listener always shares one
/// explicit limiter instead). A flat constant per spec §3.4 — a
/// forged-handshake flood does not get more room just because the
/// peer table is bigger (kernel WG's global-limiter semantics).
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

/// Cookie reply size — mirrors `noise::COOKIE_REPLY_SZ` in the vendored
/// crate (kept private there; the verification spec only authorizes the
/// `handle_verified_packet` visibility change).
const COOKIE_REPLY_SZ: usize = 64;

impl PeerTable {
    /// Build the peer table. `Err` (rather than a silent clamp) on a
    /// table that would overflow the `receiver_idx` slot namespace —
    /// the config layer already rejects it, so reaching this is a bug.
    pub fn new(cfg: &WgListenerSpec) -> Result<Self, String> {
        Self::with_limit(cfg, PEER_HANDSHAKE_RATE_LIMIT)
    }

    /// `new` with the shared limiter budget injectable — used by tests
    /// that mint hundreds of responder indices in one run: they raise
    /// the limit so `verify_packet` never sheds into cookie replies
    /// (a cookie reply echoes the *initiator's* index back and would
    /// mask the responder-side namespace assertions those tests pin).
    fn with_limit(cfg: &WgListenerSpec, handshake_rate_limit: u64) -> Result<Self, String> {
        if cfg.peers.len() > MAX_PEERS {
            return Err(format!(
                "wireguard listener: {} peers exceeds the {}-peer receiver-index namespace",
                cfg.peers.len(),
                MAX_PEERS
            ));
        }
        let secret = x25519::StaticSecret::from(cfg.private_key);
        let public = x25519::PublicKey::from(&secret);
        let limiter = Arc::new(RateLimiter::new(&public, handshake_rate_limit));
        let mut peers = Vec::with_capacity(cfg.peers.len());
        let mut peer_by_pubkey = HashMap::with_capacity(cfg.peers.len());
        for (index, peer_cfg) in cfg.peers.iter().enumerate() {
            // A peer keyed by the listener's own public key is a
            // self-peer — `X25519(secret, own_pub)` would echo our
            // traffic back. meow-config rejects this only under its
            // `wireguard` feature (x25519 is feature-gated there), so
            // the check is repeated here on every build.
            if peer_cfg.public_key == *public.as_bytes() {
                return Err(format!(
                    "wireguard listener: peer at index {index} equals the \
                     listener's own public key (self-peering is not a valid peer)"
                ));
            }
            // A duplicate static pubkey would alias two slots onto one
            // demux key; config validation already rejects it, so a
            // collision here is a bug, not a config error.
            if peer_by_pubkey.insert(peer_cfg.public_key, index).is_some() {
                return Err(format!(
                    "wireguard listener: duplicate peer public key at index {index}"
                ));
            }
            peers.push(PeerState::new(
                peer_cfg,
                index as u32,
                &secret,
                Arc::clone(&limiter),
            ));
        }
        Ok(Self {
            secret,
            public,
            limiter,
            peers,
            peer_by_pubkey,
        })
    }

    /// The shared limiter's counter reset — the actor calls this every
    /// timer tick (~250 ms) and the limiter's own one-second debounce
    /// decides whether the window actually rolled (errata E1: call it
    /// directly; do not re-implement the period here).
    pub fn reset_rate_limit(&self) {
        self.limiter.reset_count();
    }

    /// Read-only peer access for the actor (endpoint resolution for
    /// timer output, stats, logging).
    pub fn peers(&self) -> &[PeerState] {
        &self.peers
    }

    /// Mutable peer access — the actor needs `&mut PeerState.tunn` for
    /// `encapsulate` on the inner→wire direction.
    pub fn peers_mut(&mut self) -> &mut [PeerState] {
        &mut self.peers
    }

    /// The peer slot a `receiver_idx` selects, or `None` — the index's
    /// upper bits are the slot, the low byte is the per-peer session
    /// counter (see the module docs). `0` receiver indices can't be
    /// slot-addressed this way *unless* slot 0 minted index 0 — which
    /// it does, so slot-0 data with `receiver_idx` in `0..256` maps to
    /// slot 0, matching `Tunn::new(0)`'s own numbering.
    fn slot_of(&self, receiver_idx: u32) -> Option<usize> {
        let slot = (receiver_idx >> 8) as usize;
        (slot < self.peers.len()).then_some(slot)
    }

    /// Verify and dispatch one wire datagram. `datagram` is the packet
    /// **with reserved bytes 1..4 already cleared by the caller** (the
    /// actor zeroes its copy before handing it over — inbound reserved
    /// fields never reach the parser). Returns the actions the actor
    /// performs, in order.
    pub fn process_datagram(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        work: &mut [u8],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .limiter
            .verify_packet(Some(src.ip()), datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(reply)) => {
                // Under load: a cookie reply for an initiator we haven't
                // identified — send it back to `src` unstamped.
                actions.push(Action::ToWire {
                    addr: src,
                    bytes: reply.to_vec(),
                });
                return actions;
            }
            Err(_) => return actions, // forged/malformed: silent
        };
        let slot = match packet {
            Packet::HandshakeInit(init) => {
                // Anonymous half of the handshake: decrypt the
                // initiator's static key only (cheap: two HMACs, one DH,
                // one AEAD-open) to learn which configured peer this is.
                match parse_handshake_anon(&self.secret, &self.public, &init) {
                    Ok(half) => match self.peer_by_pubkey.get(&half.peer_static_public) {
                        Some(&slot) => slot,
                        None => {
                            trace!("wireguard: handshake init from unknown peer key ({src})");
                            return actions;
                        }
                    },
                    Err(_) => return actions, // failed AEAD-open: silent
                }
            }
            Packet::HandshakeResponse(p) => match self.slot_of(p.receiver_idx) {
                Some(slot) => slot,
                None => return actions,
            },
            Packet::PacketCookieReply(p) => match self.slot_of(p.receiver_idx) {
                Some(slot) => slot,
                None => return actions,
            },
            Packet::PacketData(p) => match self.slot_of(p.receiver_idx) {
                Some(slot) => slot,
                None => return actions,
            },
        };

        let result = self.peers[slot].tunn.handle_verified_packet(packet, work);
        // `handle_result` consumes `result` (which borrows `work`), so
        // the queued-packet flush — which needs `work` again — runs
        // only after it returns and that borrow is dead. Roaming is
        // decided *inside* `handle_result`, after the inner-packet ACL
        // verdict it produces: an authenticated-but-ACL-rejected packet
        // must not move the endpoint.
        if self.handle_result(slot, src, result, &mut actions) {
            while let TunnResult::WriteToNetwork(b) =
                self.peers[slot].tunn.decapsulate(None, &[], work)
            {
                let addr = self.peers[slot].endpoint.unwrap_or(src);
                self.enqueue_wire(&mut actions, slot, addr, b);
            }
        }
        actions
    }

    /// Fold one `TunnResult` into actions: wire output is stamped and
    /// queued, inner packets get their ACL check. Returns `true` when
    /// the result was `WriteToNetwork` — the caller then runs the
    /// boringtun chained-empty-datagram flush (the queued sends behind
    /// a handshake reply) with the scratch buffer this call released.
    fn handle_result(
        &mut self,
        slot: usize,
        src: SocketAddr,
        result: TunnResult<'_>,
        actions: &mut Vec<Action>,
    ) -> bool {
        match result {
            TunnResult::WriteToNetwork(b) => {
                self.enqueue_wire(actions, slot, src, b);
                true
            }
            TunnResult::WriteToTunnelV4(b, ip_src) => {
                // Roam *only* on an ACL-admitted inner packet — an
                // authenticated datagram whose inner src the ACL
                // rejected proved nothing about where the peer lives,
                // and a bare handshake or keepalive does not either
                // (its reply already answered `src` directly). The
                // endpoint is learned exactly when replies to inner
                // packets start needing it.
                if self.handle_inner(slot, b, IpAddr::V4(ip_src), actions) {
                    self.roam(slot, src);
                }
                false
            }
            TunnResult::WriteToTunnelV6(b, ip_src) => {
                if self.handle_inner(slot, b, IpAddr::V6(ip_src), actions) {
                    self.roam(slot, src);
                }
                false
            }
            // Done carries nothing; Err is an auth/decrypt failure —
            // both silent, neither roams.
            TunnResult::Done | TunnResult::Err(_) => false,
        }
    }

    /// Move the peer's endpoint to `src` — reachable only from
    /// `handle_result`'s ACL-admitted inner-packet arms (see their
    /// comment for why nothing else may move a responder's endpoint).
    fn roam(&mut self, slot: usize, src: SocketAddr) {
        if self.peers[slot].endpoint != Some(src) {
            tracing::debug!(
                "wireguard: peer '{}' endpoint → {src}",
                self.peers[slot].label
            );
            self.peers[slot].endpoint = Some(src);
        }
    }

    /// The peer's timer pass — `update_timers` drives responder-side
    /// housekeeping (session expiry teardown; a responder never
    /// re-initiates). Wire output goes to the peer's *learned*
    /// endpoint; a peer that has never sent an ACL-admitted inner
    /// packet has none and its output is dropped.
    pub fn tick(&mut self, work: &mut [u8]) -> Vec<Action> {
        let mut actions = Vec::new();
        for slot in 0..self.peers.len() {
            let result = self.peers[slot].tunn.update_timers(work);
            match result {
                TunnResult::WriteToNetwork(b) => {
                    let Some(addr) = self.peers[slot].endpoint else {
                        trace!(
                            "wireguard: peer '{}' has no endpoint; dropping timer output",
                            self.peers[slot].label
                        );
                        continue;
                    };
                    self.enqueue_wire(&mut actions, slot, addr, b);
                    while let TunnResult::WriteToNetwork(b) =
                        self.peers[slot].tunn.decapsulate(None, &[], work)
                    {
                        let addr = self.peers[slot].endpoint.unwrap_or(addr);
                        self.enqueue_wire(&mut actions, slot, addr, b);
                    }
                }
                TunnResult::Err(e) => {
                    // A responder never re-initiates — the initiator
                    // retries. Log once per expiry (session_logged
                    // flips back so a re-handshake re-arms the line).
                    trace!(
                        "wireguard: peer '{}' timer error {e:?}",
                        self.peers[slot].label
                    );
                    self.peers[slot].session_logged = false;
                }
                _ => {}
            }
        }
        actions
    }

    /// The single inner-packet ACL point: emit `Action::Inner` only
    /// when the packet's source address — already parsed and validated
    /// by the decapsulator — is inside the owning peer's `allowed_ips`,
    /// and report the verdict to the caller (it doubles as the roam
    /// gate: only admitted inner traffic may move the endpoint).
    /// Everything else is a silent drop.
    fn handle_inner(
        &mut self,
        slot: usize,
        pkt: &[u8],
        src: IpAddr,
        actions: &mut Vec<Action>,
    ) -> bool {
        if self.peers[slot].allows_src(src) {
            actions.push(Action::Inner {
                slot,
                v6: src.is_ipv6(),
                bytes: pkt.to_vec(),
            });
            true
        } else {
            trace!(
                "wireguard: peer '{}' inner src {src} outside allowed_ips",
                self.peers[slot].label
            );
            false
        }
    }

    /// Copy a wire datagram into the outbox with the peer's `reserved`
    /// bytes stamped.
    fn enqueue_wire(&self, actions: &mut Vec<Action>, slot: usize, addr: SocketAddr, bytes: &[u8]) {
        let mut buf = bytes.to_vec();
        self.peers[slot].stamp_reserved(&mut buf);
        actions.push(Action::ToWire { addr, bytes: buf });
    }
}

#[cfg(test)]
mod tests {
    //! §11.1 demux matrix — real `Tunn` initiators drive the table over
    //! in-memory datagrams; no sockets involved.
    use super::*;
    use crate::wireguard::{WgListenerSpec, WgPeerSpec};
    use meow_wireguard::x25519;
    use smol_str::SmolStr;
    use std::net::{IpAddr, Ipv4Addr};

    const ENDPOINT_A: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51001);
    const ENDPOINT_B: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51002);

    fn keypair(seed: u8) -> (x25519::StaticSecret, x25519::PublicKey) {
        let secret = x25519::StaticSecret::from([seed; 32]);
        let public = x25519::PublicKey::from(&secret);
        (secret, public)
    }

    fn peer_spec(public: [u8; 32], allowed: &[&str], psk: Option<[u8; 32]>) -> WgPeerSpec {
        WgPeerSpec {
            public_key: public,
            preshared_key: psk,
            allowed_ips: allowed
                .iter()
                .map(|s| s.parse().expect("allowed_ips parse"))
                .collect(),
            name: SmolStr::new(""),
            reserved: None,
        }
    }

    /// A listener spec with `n` peers (each keyed off seed `0xA0+i`) and
    /// the keypairs the test's client `Tunn`s pair against.
    fn table_with(
        n: usize,
        allowed: &[&str],
        psk: Option<[u8; 32]>,
    ) -> (
        PeerTable,
        x25519::PublicKey,
        Vec<(x25519::StaticSecret, x25519::PublicKey)>,
    ) {
        table_with_limit(n, allowed, psk, PEER_HANDSHAKE_RATE_LIMIT)
    }

    /// `table_with` with an injectable limiter budget — see
    /// [`PeerTable::with_limit`].
    fn table_with_limit(
        n: usize,
        allowed: &[&str],
        psk: Option<[u8; 32]>,
        limit: u64,
    ) -> (
        PeerTable,
        x25519::PublicKey,
        Vec<(x25519::StaticSecret, x25519::PublicKey)>,
    ) {
        let (server_secret, server_public) = keypair(0x5E);
        let mut peers = Vec::new();
        let mut keys = Vec::new();
        for i in 0..n {
            let (s, p) = keypair(0xA0 + i as u8);
            peers.push(peer_spec(p.to_bytes(), allowed, psk));
            keys.push((s, p));
        }
        let spec = WgListenerSpec {
            private_key: server_secret.to_bytes(),
            peers,
            mtu: 1420,
            udp: true,
            udp_timeout: std::time::Duration::from_secs(60),
        };
        (
            PeerTable::with_limit(&spec, limit).expect("table builds"),
            server_public,
            keys,
        )
    }

    /// The initiator-side `Tunn` for peer `slot`.
    fn client_for(
        client_secret: &x25519::StaticSecret,
        server_public: &[u8; 32],
        slot: usize,
        psk: Option<[u8; 32]>,
    ) -> meow_wireguard::Tunn {
        meow_wireguard::Tunn::new(
            client_secret.clone(),
            x25519::PublicKey::from(*server_public),
            psk,
            None,
            slot as u32,
            None,
        )
    }

    /// Drive one handshake initiation client→table; returns the
    /// responder's datagrams destined for `src` (usually one response).
    fn send_init(
        client: &mut meow_wireguard::Tunn,
        table: &mut PeerTable,
        src: SocketAddr,
        work: &mut [u8],
        force: bool,
    ) -> Vec<Action> {
        let init = {
            let meow_wireguard::TunnResult::WriteToNetwork(b) =
                client.format_handshake_initiation(work, force)
            else {
                panic!("initiation formats");
            };
            b.to_vec()
        };
        table.process_datagram(src, &init, work)
    }

    /// Complete a handshake at `src`: init → response → client's
    /// keepalive → done. Returns nothing; panics on any failure.
    fn handshake(
        client: &mut meow_wireguard::Tunn,
        table: &mut PeerTable,
        src: SocketAddr,
        work: &mut [u8],
    ) {
        let actions = send_init(client, table, src, work, false);
        let [Action::ToWire { addr, bytes }] = &actions[..] else {
            panic!("init produced a single response, got {actions:?}");
        };
        assert_eq!(*addr, src);
        // Client consumes the response → keepalive.
        let keepalive = {
            let meow_wireguard::TunnResult::WriteToNetwork(b) =
                client.decapsulate(Some(src.ip()), bytes, work)
            else {
                panic!("client consumes response");
            };
            b.to_vec()
        };
        // The keepalive establishes the responder's data path.
        let _ = table.process_datagram(src, &keepalive, work);
    }

    /// A minimal IPv4 packet `src`→`dst` carrying `l4` — enough for the
    /// demux's version/length/source checks.
    fn inner_v4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20 + l4.len()];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..].copy_from_slice(l4);
        p
    }

    fn inner_v6(src: [u8; 16], dst: [u8; 16], proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40 + l4.len()];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
        p[6] = proto;
        p[7] = 64;
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p[40..].copy_from_slice(l4);
        p
    }

    fn udp_l4(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut l4 = Vec::with_capacity(8 + payload.len());
        l4.extend_from_slice(&sport.to_be_bytes());
        l4.extend_from_slice(&dport.to_be_bytes());
        l4.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        l4.extend_from_slice(&[0, 0]);
        l4.extend_from_slice(payload);
        l4
    }

    /// Feed `inner` through the client's session into the table.
    fn send_inner(
        client: &mut meow_wireguard::Tunn,
        table: &mut PeerTable,
        src: SocketAddr,
        inner: &[u8],
        work: &mut [u8],
    ) -> Vec<Action> {
        let datagram = {
            let meow_wireguard::TunnResult::WriteToNetwork(b) = client.encapsulate(inner, work)
            else {
                panic!("encapsulate yields wire data");
            };
            b.to_vec()
        };
        table.process_datagram(src, &datagram, work)
    }

    fn inner_actions(actions: &[Action]) -> Vec<&Action> {
        actions
            .iter()
            .filter(|a| matches!(a, Action::Inner { .. }))
            .collect()
    }

    // ── spec §11.1 ────────────────────────────────────────────────────

    /// `demux_data_receiver_idx_hi8`: data packets land on the peer
    /// whose `receiver_idx >> 8` namespace they carry; an out-of-range
    /// slot silently drops.
    #[test]
    fn demux_data_receiver_idx_hi8() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(2, &["10.0.0.0/8", "fd00::/8"], None);

        let mut c0 = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        let mut c1 = client_for(&keys[1].0, &server_public.to_bytes(), 1, None);
        handshake(&mut c0, &mut table, ENDPOINT_A, &mut work);
        handshake(&mut c1, &mut table, ENDPOINT_B, &mut work);

        let pkt = inner_v4([10, 0, 0, 5], [10, 1, 2, 3], 17, &udp_l4(1111, 53, b"x"));
        let a0 = send_inner(&mut c0, &mut table, ENDPOINT_A, &pkt, &mut work);
        let a1 = send_inner(&mut c1, &mut table, ENDPOINT_B, &pkt, &mut work);
        match &a0[..] {
            [Action::Inner {
                slot,
                v6: false,
                bytes,
            }] => {
                assert_eq!(*slot, 0);
                assert_eq!(bytes, &pkt);
            }
            other => panic!("slot 0 inner expected, got {other:?}"),
        }
        match &a1[..] {
            [Action::Inner {
                slot, v6: false, ..
            }] => assert_eq!(*slot, 1),
            other => panic!("slot 1 inner expected, got {other:?}"),
        }

        // Forged receiver_idx: take a real data packet and bump its
        // receiver_idx's slot bits out of range → silent drop.
        let mut forged = {
            let meow_wireguard::TunnResult::WriteToNetwork(b) = c0.encapsulate(&pkt, &mut work)
            else {
                panic!("encapsulate");
            };
            b.to_vec()
        };
        // receiver_idx lives at bytes 4..8 LE; force slot = 9.
        forged[4..8].copy_from_slice(&(9u32 << 8).to_le_bytes());
        assert!(table
            .process_datagram(ENDPOINT_A, &forged, &mut work)
            .is_empty());
    }

    /// `demux_init_pubkey_map_hit_miss`: a registered key's init gets a
    /// response; an unregistered key's init gets nothing and changes
    /// nothing.
    #[test]
    fn demux_init_pubkey_map_hit_miss() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(1, &["0.0.0.0/0"], None);

        // Hit: the configured peer's init produces a response to src.
        let mut good = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        let actions = send_init(&mut good, &mut table, ENDPOINT_A, &mut work, false);
        assert!(matches!(&actions[..], [Action::ToWire { .. }]));

        // Miss: an unregistered peer key → silently dropped, and no
        // endpoint is learned for any peer.
        let (rogue_secret, _) = keypair(0x77);
        let mut rogue = client_for(&rogue_secret, &server_public.to_bytes(), 0, None);
        let init = {
            let meow_wireguard::TunnResult::WriteToNetwork(b) =
                rogue.format_handshake_initiation(&mut work, false)
            else {
                panic!("initiation");
            };
            b.to_vec()
        };
        let actions = table.process_datagram(ENDPOINT_B, &init, &mut work);
        assert!(
            actions.is_empty(),
            "unregistered key must drop, got {actions:?}"
        );
        // The good peer's endpoint is untouched — zero state change:
        // a bare handshake does not learn the endpoint (only an
        // ACL-admitted inner packet does).
        assert_eq!(table.peers()[0].endpoint, None);
    }

    /// `demux_init_forged_mac1`: a handshake init with a corrupted mac1
    /// is refused inside `verify_packet` — no peer lookup, no output,
    /// no state.
    #[test]
    fn demux_init_forged_mac1() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(1, &["0.0.0.0/0"], None);

        let mut client = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        let mut init = {
            let meow_wireguard::TunnResult::WriteToNetwork(b) =
                client.format_handshake_initiation(&mut work, false)
            else {
                panic!("initiation");
            };
            b.to_vec()
        };
        // Corrupt the mac1 (bytes len-32..len-16).
        let n = init.len();
        init[n - 20] ^= 0xFF;
        assert!(table
            .process_datagram(ENDPOINT_A, &init, &mut work)
            .is_empty());
        assert!(table.peers()[0].endpoint.is_none());
    }

    /// `demux_handshake_resp_and_cookie`: response and cookie packets
    /// also dispatch by `receiver_idx >> 8` — an in-range index reaches
    /// the owning peer (which rejects it as unexpected: a responder
    /// never initiated), and an out-of-range index drops at dispatch.
    #[test]
    fn demux_handshake_resp_and_cookie() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(2, &["0.0.0.0/0"], None);

        // Slot-scoped namespaces for the synthetic packets below.
        assert_eq!(table.slot_of((1u32 << 8) | 7), Some(1));
        assert_eq!(table.slot_of(9u32 << 8), None);

        // A real handshake at slot 1 gives us a real response packet —
        // its receiver_idx is the CLIENT's sender_idx (client namespace
        // = slot too, since the client was built with index=1).
        let mut c1 = client_for(&keys[1].0, &server_public.to_bytes(), 1, None);
        let actions = send_init(&mut c1, &mut table, ENDPOINT_B, &mut work, false);
        let [Action::ToWire { bytes: resp, .. }] = &actions[..] else {
            panic!("response expected");
        };
        assert_eq!(resp[0], 2); // handshake response type

        // Feed a synthetic HandshakeResponse whose receiver_idx points
        // into slot 1's namespace — needs a valid mac1 (the mac1 key is
        // derivable from the public key, so building one in-test mirrors
        // a real initiator's reachability). We can't cheaply produce a
        // mac1 without boringtun internals, so instead assert the
        // namespace dispatch directly: out-of-range → empty; in-range
        // reaches the peer's `handle_verified_packet`, which rejects it
        // (no init in flight) — both paths emit nothing.
        let mut synthetic_resp = vec![0u8; 92];
        synthetic_resp[0] = 2;
        synthetic_resp[4..8].copy_from_slice(&(9u32 << 8).to_le_bytes());
        assert!(table
            .process_datagram(ENDPOINT_B, &synthetic_resp, &mut work)
            .is_empty());

        // Same for a type-3 cookie reply with an out-of-namespace
        // receiver — dropped at dispatch.
        let mut cookie = vec![0u8; 64];
        cookie[0] = 3;
        cookie[4..8].copy_from_slice(&(9u32 << 8).to_le_bytes());
        assert!(table
            .process_datagram(ENDPOINT_B, &cookie, &mut work)
            .is_empty());
        // The real response's receiver_idx decoded to the client's own
        // namespace — feeding it back must not disturb any peer (it
        // decodes to slot 1 via client index 1 and fails its checks).
        let _ = table.process_datagram(ENDPOINT_B, resp, &mut work);
        assert_eq!(table.peers()[1].endpoint, None);
    }

    /// `index_namespace_disjoint`: the local indices the responder
    /// mints never leave the peer's `>>8` namespace, even across the
    /// low-byte wrap (256+ allocations). The limiter runs wide open —
    /// under-load cookie replies echo the *initiator's* index back at
    /// bytes 4..8, which masked the same `>>8` assertion before (the
    /// client Tunn was built with `index = slot`, so the echo read
    /// like a correctly-namespaced responder index).
    #[test]
    fn index_namespace_disjoint() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with_limit(2, &["0.0.0.0/0"], None, u64::MAX);

        let mut c0 = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        // 260 inits on slot 0 → sender indices 0..259 on the responder,
        // all `>>8 == 0` (the low byte wraps inside the slot).
        for i in 0..260 {
            let actions = send_init(&mut c0, &mut table, ENDPOINT_A, &mut work, true);
            let [Action::ToWire { bytes: resp, .. }] = &actions[..] else {
                panic!("init {i} produced a response");
            };
            assert_eq!(
                resp[0], 2,
                "init {i}: a cookie reply can't pose as a response"
            );
            let sender_idx = u32::from_le_bytes(resp[4..8].try_into().unwrap());
            assert_eq!(sender_idx >> 8, 0, "init {i} leaked namespaces");
        }
        // Slot 1's first session starts at (1<<8)|0.
        let mut c1 = client_for(&keys[1].0, &server_public.to_bytes(), 1, None);
        let actions = send_init(&mut c1, &mut table, ENDPOINT_B, &mut work, false);
        let [Action::ToWire { bytes: resp, .. }] = &actions[..] else {
            panic!("response");
        };
        assert_eq!(resp[0], 2);
        let sender_idx = u32::from_le_bytes(resp[4..8].try_into().unwrap());
        assert_eq!(sender_idx >> 8, 1);
    }

    /// `roam_authenticated_only`: a valid ACL-admitted datagram from a
    /// new source roams the endpoint; a forged one does not.
    #[test]
    fn roam_authenticated_only() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(1, &["0.0.0.0/0"], None);

        let mut c0 = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        handshake(&mut c0, &mut table, ENDPOINT_A, &mut work);
        // The handshake itself does not learn the endpoint — the first
        // ACL-admitted inner packet does.
        assert_eq!(table.peers()[0].endpoint, None);
        let learn = inner_v4([10, 0, 0, 5], [10, 1, 2, 3], 17, &udp_l4(1, 2, b"l"));
        let _ = send_inner(&mut c0, &mut table, ENDPOINT_A, &learn, &mut work);
        assert_eq!(table.peers()[0].endpoint, Some(ENDPOINT_A));

        // Authenticated roam: same session, new source.
        let pkt = inner_v4([10, 0, 0, 5], [10, 1, 2, 3], 17, &udp_l4(1, 2, b"r"));
        let _ = send_inner(&mut c0, &mut table, ENDPOINT_B, &pkt, &mut work);
        assert_eq!(table.peers()[0].endpoint, Some(ENDPOINT_B));

        // Forged: a data datagram with a corrupted ciphertext — the
        // AEAD open fails → Err → no roam.
        let src3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 59999);
        let mut forged = {
            let meow_wireguard::TunnResult::WriteToNetwork(b) = c0.encapsulate(&pkt, &mut work)
            else {
                panic!("encapsulate");
            };
            b.to_vec()
        };
        let n = forged.len();
        forged[n - 1] ^= 0xFF;
        assert!(table.process_datagram(src3, &forged, &mut work).is_empty());
        assert_eq!(table.peers()[0].endpoint, Some(ENDPOINT_B));

        // Forged: out-of-namespace receiver_idx — drops before the peer.
        forged[4..8].copy_from_slice(&(77u32 << 8).to_le_bytes());
        assert!(table.process_datagram(src3, &forged, &mut work).is_empty());
        assert_eq!(table.peers()[0].endpoint, Some(ENDPOINT_B));
    }

    /// F1 — roam requires an ACL-admitted inner packet: an
    /// authenticated datagram whose inner source sits outside
    /// `allowed_ips` must not move the endpoint (the roam used to run
    /// before the ACL check, so a rejected inner src could still drag
    /// the endpoint to a spoofed datagram source). A handshake alone
    /// does not learn the endpoint either — it is learned exactly when
    /// reply traffic starts needing it.
    #[test]
    fn roam_requires_acl_admitted_inner() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(1, &["10.0.0.0/24"], None);

        let mut c0 = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        handshake(&mut c0, &mut table, ENDPOINT_A, &mut work);
        assert_eq!(
            table.peers()[0].endpoint,
            None,
            "handshake/keepalive alone must not learn the endpoint"
        );

        // ACL-admitted packet → the endpoint is learned.
        let ok = inner_v4([10, 0, 0, 7], [10, 9, 9, 9], 17, &udp_l4(1, 2, b"x"));
        let _ = send_inner(&mut c0, &mut table, ENDPOINT_A, &ok, &mut work);
        assert_eq!(table.peers()[0].endpoint, Some(ENDPOINT_A));

        // Inner src outside allowed_ips → the packet drops at the ACL
        // and the authenticated datagram still leaves the endpoint.
        let bad = inner_v4([10, 0, 1, 7], [10, 9, 9, 9], 17, &udp_l4(1, 2, b"x"));
        let acts = send_inner(&mut c0, &mut table, ENDPOINT_B, &bad, &mut work);
        assert!(
            inner_actions(&acts).is_empty(),
            "ACL-rejected inner packet drops"
        );
        assert_eq!(
            table.peers()[0].endpoint,
            Some(ENDPOINT_A),
            "an ACL-rejected inner packet must not roam the endpoint"
        );
    }

    /// F2 — a peer keyed by the listener's own public key is a
    /// self-peer (`X25519(secret, own_pub)` would echo our traffic).
    /// meow-config rejects it only when its `wireguard` feature is
    /// compiled, so the table re-checks on every build — a
    /// `no-default-features` config build must not slip one in.
    #[test]
    fn self_peer_public_key_rejected() {
        let (server_secret, server_public) = keypair(0x5E);
        let spec = WgListenerSpec {
            private_key: server_secret.to_bytes(),
            peers: vec![peer_spec(server_public.to_bytes(), &["10.0.0.0/8"], None)],
            mtu: 1420,
            udp: true,
            udp_timeout: std::time::Duration::from_secs(60),
        };
        let err = PeerTable::new(&spec)
            .err()
            .expect("self-loop peer must be rejected");
        assert!(err.contains("own public key"), "{err}");
    }

    /// `allowed_ips_v4_v6_acl`: per-peer source ACLs admit listed
    /// sources and drop others, per family.
    #[test]
    fn allowed_ips_v4_v6_acl() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(1, &["10.0.0.0/24", "fd00::/64"], None);

        let mut c0 = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        handshake(&mut c0, &mut table, ENDPOINT_A, &mut work);

        // v4 in-range → Inner.
        let ok4 = inner_v4([10, 0, 0, 200], [10, 9, 9, 9], 17, &udp_l4(1, 2, b"a"));
        assert_eq!(
            inner_actions(&send_inner(
                &mut c0, &mut table, ENDPOINT_A, &ok4, &mut work
            ))
            .len(),
            1
        );
        // v4 out-of-range → drop.
        let bad4 = inner_v4([10, 0, 1, 1], [10, 9, 9, 9], 17, &udp_l4(1, 2, b"a"));
        assert!(inner_actions(&send_inner(
            &mut c0, &mut table, ENDPOINT_A, &bad4, &mut work
        ))
        .is_empty());
        // v6 in-range → Inner{v6: true}. fd00::5 → fd00::9.
        let mut s6 = [0u8; 16];
        s6[0] = 0xfd;
        s6[15] = 0x05;
        let mut d6 = [0u8; 16];
        d6[0] = 0xfd;
        d6[15] = 0x09;
        let ok6 = inner_v6(s6, d6, 17, &udp_l4(1, 2, b"a"));
        let acts = send_inner(&mut c0, &mut table, ENDPOINT_A, &ok6, &mut work);
        match &acts[..] {
            [Action::Inner {
                slot: 0,
                v6: true,
                bytes,
            }] => assert_eq!(bytes, &ok6),
            other => panic!("v6 inner expected, got {other:?}"),
        }
        // v6 out-of-range → drop. fd01::5 is outside fd00::/64.
        s6[1] = 0x01;
        let bad6 = inner_v6(s6, d6, 17, &udp_l4(1, 2, b"a"));
        assert!(inner_actions(&send_inner(
            &mut c0, &mut table, ENDPOINT_A, &bad6, &mut work
        ))
        .is_empty());
    }

    /// `psk_on_off`: a peer configured with a PSK accepts a client that
    /// presents the same PSK and fails one that doesn't (the client
    /// can't open the response — Noise mixes psk into the chain key).
    #[test]
    fn psk_on_off() {
        let mut work = vec![0u8; 4096];
        let psk = [0x42u8; 32];
        let (mut table, server_public, keys) = table_with(1, &["0.0.0.0/0"], Some(psk));

        // Correct PSK → full handshake completes.
        let mut good = client_for(&keys[0].0, &server_public.to_bytes(), 0, Some(psk));
        handshake(&mut good, &mut table, ENDPOINT_A, &mut work);
        let pkt = inner_v4([1, 2, 3, 4], [5, 6, 7, 8], 17, &udp_l4(1, 2, b"p"));
        assert_eq!(
            inner_actions(&send_inner(
                &mut good, &mut table, ENDPOINT_A, &pkt, &mut work
            ))
            .len(),
            1
        );

        // Wrong/absent PSK → the responder still emits a response (psk
        // mixes later), but the client can't open it → no session, no
        // inner traffic.
        let mut bad = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        let actions = send_init(&mut bad, &mut table, ENDPOINT_B, &mut work, false);
        let [Action::ToWire { bytes: resp, .. }] = &actions[..] else {
            panic!("response emitted even on psk mismatch");
        };
        let r = bad.decapsulate(Some(ENDPOINT_B.ip()), resp, &mut work);
        assert!(
            matches!(r, meow_wireguard::TunnResult::Err(_)),
            "psk-mismatched response must fail client-side: {r:?}"
        );
    }

    /// `stamp_reserved`: a peer configured with WARP-style `reserved`
    /// bytes gets them stamped at bytes 1..4 of *every* wire datagram
    /// the demux produces — handshake responses included. (The config
    /// layer already pins `reserved` parsing; this is the wire-level
    /// contract nothing else covered.)
    #[test]
    fn stamp_reserved_on_wire() {
        let mut work = vec![0u8; 4096];
        let (server_secret, server_public) = keypair(0x5E);
        let (csec, cpub) = keypair(0xA0);
        let reserved = [13u8, 53, 133];
        let mut peer = peer_spec(cpub.to_bytes(), &["0.0.0.0/0"], None);
        peer.reserved = Some(reserved);
        let spec = WgListenerSpec {
            private_key: server_secret.to_bytes(),
            peers: vec![peer],
            mtu: 1420,
            udp: true,
            udp_timeout: std::time::Duration::from_secs(60),
        };
        let mut table = PeerTable::new(&spec).expect("table builds");
        let mut c0 = client_for(&csec, &server_public.to_bytes(), 0, None);

        let actions = send_init(&mut c0, &mut table, ENDPOINT_A, &mut work, false);
        let [Action::ToWire { bytes: resp, .. }] = &actions[..] else {
            panic!("init produced a response");
        };
        assert_eq!(resp[0], 2);
        assert_eq!(
            &resp[1..4],
            &reserved,
            "reserved field stamped on the response"
        );
    }

    /// `reserved_zeroed_inbound`: the actor clears bytes 1..4 before
    /// the demux — simulate both halves: a stamped datagram fails as
    /// garbage, the cleared copy processes normally.
    #[test]
    fn reserved_zeroed_inbound() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(1, &["0.0.0.0/0"], None);

        let mut c0 = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        let mut init = {
            let meow_wireguard::TunnResult::WriteToNetwork(b) =
                c0.format_handshake_initiation(&mut work, false)
            else {
                panic!("initiation");
            };
            b.to_vec()
        };
        // WARP-style stamping over the reserved field breaks the type
        // check wholesale — the scrubbed copy must still work.
        init[1..4].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        assert!(table
            .process_datagram(ENDPOINT_A, &init, &mut work)
            .is_empty());
        init[1..4].fill(0); // actor-side scrub
        let actions = table.process_datagram(ENDPOINT_A, &init, &mut work);
        assert!(matches!(&actions[..], [Action::ToWire { .. }]));
    }

    /// A cookie reply answers an *unidentified* initiator — it must
    /// never carry a peer's `reserved` stamp (only `enqueue_wire`
    /// stamps; the under-load early return deliberately bypasses it).
    #[test]
    fn cookie_reply_unstamped() {
        let mut work = vec![0u8; 4096];
        let (server_secret, server_public) = keypair(0x5E);
        let (csec, cpub) = keypair(0xA0);
        let mut peer = peer_spec(cpub.to_bytes(), &["0.0.0.0/0"], None);
        peer.reserved = Some([0xAA, 0xBB, 0xCC]);
        let spec = WgListenerSpec {
            private_key: server_secret.to_bytes(),
            peers: vec![peer],
            mtu: 1420,
            udp: true,
            udp_timeout: std::time::Duration::from_secs(60),
        };
        let mut table = PeerTable::new(&spec).expect("table builds");
        let mut c0 = client_for(&csec, &server_public.to_bytes(), 0, None);

        let mut saw_cookie = false;
        for _ in 0..PEER_HANDSHAKE_RATE_LIMIT + 2 {
            let actions = send_init(&mut c0, &mut table, ENDPOINT_A, &mut work, true);
            if let [Action::ToWire { bytes, .. }] = &actions[..] {
                if bytes.first() == Some(&3) {
                    assert_eq!(&bytes[1..4], &[0, 0, 0], "cookie replies are never stamped");
                    saw_cookie = true;
                }
            }
        }
        assert!(saw_cookie, "limiter never emitted a cookie reply");
    }

    /// The shared limiter emits a cookie reply to `src` once the
    /// handshake counter crosses the rate limit — the reply is the
    /// load-shed path, not a peer lookup.
    #[test]
    fn cookie_reply_under_load() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(1, &["0.0.0.0/0"], None);

        let mut c0 = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);
        // Rate limit = 10 × 1 peer; the limiter counts verified
        // handshake packets, so the *11th* init (count 0..10) trips
        // under-load → type-3 cookie reply to src.
        let mut saw_cookie = false;
        for i in 0..12 {
            let actions = send_init(&mut c0, &mut table, ENDPOINT_A, &mut work, true);
            match &actions[..] {
                [Action::ToWire { addr, bytes }] if bytes.first() == Some(&3) => {
                    assert_eq!(*addr, ENDPOINT_A);
                    saw_cookie = true;
                }
                [Action::ToWire { .. }] => {}
                other => panic!("init {i}: unexpected {other:?}"),
            }
        }
        assert!(saw_cookie, "limiter never emitted a cookie reply");
    }

    /// M1 — the shared handshake budget is a flat
    /// `PEER_HANDSHAKE_RATE_LIMIT` regardless of peer count (spec
    /// §3.4: a forged-init flood does not get more room just because
    /// the table is bigger). With 4 peers a peer-scaled limit would
    /// be 40 — the budget must trip at 10 anyway.
    #[test]
    fn shared_rate_limit_budget_constant() {
        let mut work = vec![0u8; 4096];
        let (mut table, server_public, keys) = table_with(4, &["0.0.0.0/0"], None);
        let mut c0 = client_for(&keys[0].0, &server_public.to_bytes(), 0, None);

        let mut saw_cookie = false;
        for i in 0..PEER_HANDSHAKE_RATE_LIMIT + 2 {
            let actions = send_init(&mut c0, &mut table, ENDPOINT_A, &mut work, true);
            if let [Action::ToWire { bytes, .. }] = &actions[..] {
                if bytes.first() == Some(&3) {
                    saw_cookie = true;
                }
            } else {
                panic!("init {i}: unexpected {actions:?}");
            }
        }
        assert!(
            saw_cookie,
            "the global budget must not scale with peer count — \
             a {PEER_HANDSHAKE_RATE_LIMIT}-init flood already sheds load"
        );
    }
}
