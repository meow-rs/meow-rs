// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::PacketData;
use crate::noise::errors::WireGuardError;
#[cfg(not(feature = "wireguard-boring"))]
use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305};
use parking_lot::Mutex;
use portable_atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// PATCH(4): ring::aead::LessSafeKey fields replaced by raw key bytes; the
// AEAD cipher is constructed per operation in the crate::crypto facade (the
// same construct-per-call pattern upstream used in handshake.rs).
// PATCH(16): under `wireguard-boring` the key bytes become cached
// BoringSSL `SessionAead` contexts — key schedule runs once here instead
// of per packet.
// PATCH(18): everything a data-plane worker needs moved into
// `SessionCrypto`, held by `Arc` — the RustCrypto fallback caches a
// built `ChaCha20Poly1305` per direction the same way (the per-packet
// `new_from_slice` key schedule is gone from this path too). The ring
// keeps owning `Session`; a `SessionHandle` is an `Arc` clone of the
// same crypto, so a packet whose session rotated out of the ring
// mid-batch still decrypts, and the replay-window mutex is shared —
// never copied.
pub(crate) struct SessionCrypto {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    #[cfg(feature = "wireguard-boring")]
    receiver_ctx: crate::crypto::boring_ctx::SessionAead,
    #[cfg(feature = "wireguard-boring")]
    sender_ctx: crate::crypto::boring_ctx::SessionAead,
    #[cfg(not(feature = "wireguard-boring"))]
    receiver_cipher: ChaCha20Poly1305,
    #[cfg(not(feature = "wireguard-boring"))]
    sender_cipher: ChaCha20Poly1305,
    sending_key_counter: AtomicU64,
    receiving_key_counter: Mutex<ReceivingKeyCounterValidator>,
}

/// One noise session. The struct itself only wraps the shared
/// [`SessionCrypto`] — `Tunn`'s ring keeps owning it, workers borrow it
/// through `SessionHandle`.
pub struct Session {
    pub(crate) crypto: Arc<SessionCrypto>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.crypto.receiving_index, self.crypto.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 16; // Suffice to reorder 64*16 = 1024 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone, Default)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        // PATCH(lint): if_not_else — arms swapped, same behavior
        if self.check_bit(counter) {
            Err(WireGuardError::DuplicateCounter)
        } else {
            Ok(())
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            self.bitmap.fill(0);
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            crypto: Arc::new(SessionCrypto {
                receiving_index: local_index,
                sending_index: peer_index,
                #[cfg(feature = "wireguard-boring")]
                receiver_ctx: crate::crypto::boring_ctx::SessionAead::new(&receiving_key),
                #[cfg(feature = "wireguard-boring")]
                sender_ctx: crate::crypto::boring_ctx::SessionAead::new(&sending_key),
                // PATCH(18): the fallback builds each direction's cipher
                // once at handshake time, matching the boring build's
                // cached-ctx shape — the data path never re-runs the key
                // schedule (and a worker pass never runs it concurrently).
                #[cfg(not(feature = "wireguard-boring"))]
                receiver_cipher: ChaCha20Poly1305::new_from_slice(&receiving_key)
                    .expect("ChaCha20-Poly1305 key is always 32 bytes"),
                #[cfg(not(feature = "wireguard-boring"))]
                sender_cipher: ChaCha20Poly1305::new_from_slice(&sending_key)
                    .expect("ChaCha20-Poly1305 key is always 32 bytes"),
                sending_key_counter: AtomicU64::new(0),
                receiving_key_counter: Mutex::new(Default::default()),
            }),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.crypto.receiving_index as usize
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the size of the formatted packet
    pub(super) fn format_packet_data<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> &'a mut [u8] {
        self.crypto.format_packet_data(src, dst)
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the size of the encapsulated packet on success
    pub(super) fn receive_packet_data<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        self.crypto.receive_packet_data(packet, dst)
    }

    /// PATCH(17): in-place twin of `receive_packet_data` — see
    /// [`SessionCrypto::receive_packet_data_in_place`].
    pub(super) fn receive_packet_data_in_place(
        &self,
        receiver_idx: u32,
        counter: u64,
        ct_and_tag: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        self.crypto
            .receive_packet_data_in_place(receiver_idx, counter, ct_and_tag)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        self.crypto.current_packet_cnt()
    }
}

impl SessionCrypto {
    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock();
        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }
        ret
    }

    /// PATCH(19): block-reserve `n` sending counters, returning the base
    /// — a TX batch's job_i seals with `base + i`, so one `fetch_add`
    /// serves the whole pass instead of one per packet. `Relaxed`
    /// suffices: the counter is a nonce, so disjointness is all the
    /// wire needs — it carries no ordering dependency the memory model
    /// must publish (the receiver's replay window accepts any unseen
    /// counter inside N_BITS of its high-water mark).
    pub(crate) fn reserve_tx_counters(&self, n: usize) -> u64 {
        self.sending_key_counter
            .fetch_add(n as u64, Ordering::Relaxed)
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the size of the formatted packet
    fn format_packet_data<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> &'a mut [u8] {
        let counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed);
        let n = self.format_packet_data_at(src, dst, counter);
        &mut dst[..n]
    }

    /// PATCH(19): `format_packet_data`'s body with the counter supplied
    /// by the caller — the `&self` shape a crypto-pool worker needs
    /// (the batch's Phase A block-reserved the counter through
    /// [`reserve_tx_counters`](Self::reserve_tx_counters), so the seal
    /// never touches the atomic itself). Writes
    /// `type‖sending_index‖counter‖ciphertext‖tag` into `dst` exactly
    /// as the fetching form does and returns the wire length
    /// (`DATA_OFFSET + src.len() + AEAD_SIZE`). Same panic contract:
    /// `dst` must hold `src.len() + DATA_OVERHEAD_SZ` — the job layer
    /// guards before calling.
    pub(crate) fn format_packet_data_at(&self, src: &[u8], dst: &mut [u8], counter: u64) -> usize {
        if dst.len() < src.len() + super::DATA_OVERHEAD_SZ {
            panic!("The destination buffer is too small");
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter_field, data) = rest.split_at_mut(8);

        message_type.copy_from_slice(&super::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
        counter_field.copy_from_slice(&counter.to_le_bytes());

        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        let n = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&counter.to_le_bytes());
            data[..src.len()].copy_from_slice(src);
            // PATCH(4): seal in place via the facade, then append the tag.
            // PATCH(16): the boring build seals through the cached ctx;
            // PATCH(18): the fallback seals through the cached cipher.
            #[cfg(feature = "wireguard-boring")]
            let tag = crate::crypto::session_seal_in_place(
                &self.sender_ctx,
                nonce,
                &[],
                &mut data[..src.len()],
            );
            #[cfg(not(feature = "wireguard-boring"))]
            let tag = crate::crypto::session_seal_in_place(
                &self.sender_cipher,
                nonce,
                &[],
                &mut data[..src.len()],
            );
            data[src.len()..src.len() + AEAD_SIZE].copy_from_slice(&tag);
            src.len() + AEAD_SIZE
        };

        DATA_OFFSET + n
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the size of the encapsulated packet on success
    fn receive_packet_data<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }
        if packet.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(packet.counter)?;

        let ret = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&packet.counter.to_le_bytes());
            // PATCH(4): open in place via the facade — copies the ciphertext
            // into dst and strips the tag internally. PATCH(16): the
            // boring build opens through the cached ctx; PATCH(18): the
            // fallback opens through the cached cipher.
            #[cfg(feature = "wireguard-boring")]
            let opened = crate::crypto::session_open_in_place(
                &self.receiver_ctx,
                nonce,
                &[],
                dst,
                packet.encrypted_encapsulated_packet,
            );
            #[cfg(not(feature = "wireguard-boring"))]
            let opened = crate::crypto::session_open_in_place(
                &self.receiver_cipher,
                nonce,
                &[],
                dst,
                packet.encrypted_encapsulated_packet,
            );
            opened.map_err(|_| WireGuardError::InvalidAeadTag)?
        };

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(packet.counter)?;
        Ok(ret)
    }

    /// PATCH(17): in-place twin of `receive_packet_data` — `ct_and_tag`
    /// is the ciphertext‖tag payload region of the wire datagram itself
    /// (the receive buffer's `buf[DATA_PAYLOAD_OFF..]`), and the
    /// plaintext replaces the ciphertext where it stood instead of
    /// being copied into a caller `dst`. The buffer's own length bounds
    /// the input, so the upstream undersize-`dst` panic has no analogue
    /// here; the `WrongIndex`/counter-check/open/mark ordering is
    /// identical. Returns the plaintext length
    /// (`ct_and_tag.len() - AEAD_SIZE`) on success.
    /// PATCH(18): callable through a `SessionHandle` — the shared
    /// replay-window mutex makes concurrent opens on the same session
    /// replay-safe (the mark side of the check rejects a duplicate the
    /// quick check raced past).
    pub(crate) fn receive_packet_data_in_place(
        &self,
        receiver_idx: u32,
        counter: u64,
        ct_and_tag: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        if receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(counter)?;

        let pt_len = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&counter.to_le_bytes());
            // PATCH(17): open inside the datagram — no ciphertext copy,
            // no `dst` at all. PATCH(16): the boring build opens through
            // the cached ctx; PATCH(18): the fallback through the cached
            // cipher.
            #[cfg(feature = "wireguard-boring")]
            let opened =
                crate::crypto::session_decrypt_in_place(&self.receiver_ctx, nonce, &[], ct_and_tag);
            #[cfg(not(feature = "wireguard-boring"))]
            let opened = crate::crypto::session_decrypt_in_place(
                &self.receiver_cipher,
                nonce,
                &[],
                ct_and_tag,
            );
            opened.map_err(|_| WireGuardError::InvalidAeadTag)?
        };

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(counter)?;
        Ok(pt_len)
    }

    /// Returns the estimated downstream packet loss for this session
    fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock();
        (counter_validator.next, counter_validator.receive_cnt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }

    /// PATCH(18): the RustCrypto fallback's cached-cipher path —
    /// `Session::new` builds each direction's `ChaCha20Poly1305` once
    /// and `format_packet_data`/`receive_packet_data_in_place` use it
    /// on every packet. 100 seal→open round-trips pin both directions
    /// of that path end to end (plus the replay bit on a duplicate).
    #[cfg(not(feature = "wireguard-boring"))]
    #[test]
    fn rustcrypto_cached_cipher_round_trip() {
        // a seals under key [7] toward b; b opens under the same key.
        let a = Session::new(1, 11, [9u8; 32], [7u8; 32]);
        let b = Session::new(11, 1, [7u8; 32], [9u8; 32]);
        let mut first = None;
        for i in 0..100u64 {
            let src = format!("packet-{i}").into_bytes();
            let mut dst = vec![0u8; src.len() + crate::noise::DATA_OVERHEAD_SZ];
            let wire_len = a.format_packet_data(&src, &mut dst).len();
            if i == 0 {
                first = Some(dst[..wire_len].to_vec());
            }
            let r_idx = u32::from_le_bytes(dst[4..8].try_into().unwrap());
            let counter = u64::from_le_bytes(dst[8..16].try_into().unwrap());
            assert_eq!(r_idx, 11);
            assert_eq!(counter, i);
            let pt_len = b
                .receive_packet_data_in_place(r_idx, counter, &mut dst[DATA_OFFSET..wire_len])
                .expect("cached cipher opens");
            assert_eq!(&dst[DATA_OFFSET..DATA_OFFSET + pt_len], &src[..]);
        }
        // A replayed datagram fails the counter check — the mark side
        // of the shared validator already saw it.
        let mut dup = first.expect("kept the first datagram");
        let wire_len = dup.len();
        let r_idx = u32::from_le_bytes(dup[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(dup[8..16].try_into().unwrap());
        assert!(b
            .receive_packet_data_in_place(r_idx, counter, &mut dup[DATA_OFFSET..wire_len])
            .is_err());
    }

    /// PATCH(19): `reserve_tx_counters` hands out disjoint, internally
    /// contiguous ranges — one `fetch_add` per call no matter how the
    /// callers interleave on the shared crypto.
    #[test]
    fn tx_reserve_counters_disjoint() {
        let s = Session::new(1, 11, [9u8; 32], [7u8; 32]);
        let bases = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    bases.lock().push(s.crypto.reserve_tx_counters(16));
                });
            }
        });
        let mut bases = bases.into_inner();
        bases.sort_unstable();
        // Four threads × 16 counters: the only disjoint contiguous
        // partition of [0, 64).
        assert_eq!(bases, [0, 16, 32, 48]);
    }

    /// PATCH(19): `format_packet_data_at` reproduces
    /// `format_packet_data` byte-for-byte at the same counter — two
    /// identically-built sessions, one sealing through the fetching
    /// form, one through the caller-supplied form, must emit the same
    /// datagram (header and AEAD tag are keyed to the counter alone).
    /// Runs under both backends — the seal path is shared.
    #[test]
    fn format_packet_data_at_equivalence() {
        let a_fetch = Session::new(1, 11, [9u8; 32], [7u8; 32]);
        let a_at = Session::new(1, 11, [9u8; 32], [7u8; 32]);
        for counter in 0..32u64 {
            let src = format!("packet-{counter}").into_bytes();
            let mut d1 = vec![0u8; src.len() + crate::noise::DATA_OVERHEAD_SZ];
            let mut d2 = vec![0u8; src.len() + crate::noise::DATA_OVERHEAD_SZ];
            let n1 = a_fetch.format_packet_data(&src, &mut d1).len();
            let n2 = a_at.crypto.format_packet_data_at(&src, &mut d2, counter);
            assert_eq!(n1, n2);
            assert_eq!(&d1[..n1], &d2[..n2], "counter {counter} diverged");
        }
    }

    /// PATCH(19): 100 caller-counter seal→open round-trips, opened in a
    /// non-monotone order — `(step * 37 + 13) % 100` is a full-period
    /// permutation — pinning both the worker-side seal and the replay
    /// window's out-of-order acceptance at the far end. No cfg gate:
    /// `format_packet_data_at` is the pool's seal path under both
    /// backends.
    #[test]
    fn format_packet_data_at_round_trip() {
        let a = Session::new(1, 11, [9u8; 32], [7u8; 32]);
        let b = Session::new(11, 1, [7u8; 32], [9u8; 32]);
        let mut datagrams: Vec<Vec<u8>> = Vec::new();
        for i in 0..100u64 {
            let src = format!("packet-{i}").into_bytes();
            let mut dst = vec![0u8; src.len() + crate::noise::DATA_OVERHEAD_SZ];
            let n = a.crypto.format_packet_data_at(&src, &mut dst, i);
            dst.truncate(n);
            datagrams.push(dst);
        }
        for step in 0..100u64 {
            let i = ((step * 37 + 13) % 100) as usize;
            let mut dst = std::mem::take(&mut datagrams[i]);
            let wire_len = dst.len();
            let r_idx = u32::from_le_bytes(dst[4..8].try_into().unwrap());
            let counter = u64::from_le_bytes(dst[8..16].try_into().unwrap());
            assert_eq!(r_idx, 11);
            assert_eq!(counter, i as u64);
            let pt_len = b
                .receive_packet_data_in_place(r_idx, counter, &mut dst[DATA_OFFSET..wire_len])
                .expect("caller-counter seal opens");
            let expect = format!("packet-{i}").into_bytes();
            assert_eq!(&dst[DATA_OFFSET..DATA_OFFSET + pt_len], &expect[..]);
        }
    }
}
