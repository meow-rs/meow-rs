// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Facade replacing `ring` callsites in the vendored boringtun `noise/` module.
//! All primitives are RustCrypto crates already present in the workspace.
//!
//! IMPORTANT: the BLAKE2s MAC helpers in `noise/handshake.rs` use HMAC(BLAKE2s)
//! — RFC 2401 HMAC wrapping — NOT keyed-BLAKE2s (the `Blake2sMac` key
//! parameter). That code is NOT patched (it already uses the `blake2` crate,
//! not `ring`) and must NOT be changed to `Hmac`. See boringtun
//! `src/noise/handshake.rs`: "RFC 2401 HMAC+Blake2s, not to be confused with
//! *keyed* Blake2s".

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce,
};

/// ChaCha20-Poly1305 seal (in-place with separate tag).
/// Nonce layout: `nonce[0..4]` = `0x00`, `nonce[4..12]` = `counter.to_le_bytes()`.
/// Writes ciphertext into `dst[..data.len()]` and the tag into
/// `dst[data.len()..data.len() + 16]`; `dst` must be at least
/// `data.len() + 16` bytes.
/// Exact drop-in for what upstream called
/// `ring::aead::LessSafeKey::seal_in_place_separate_tag`.
#[inline]
pub(crate) fn aead_chacha20_seal_inner(
    dst: &mut [u8],
    key: &[u8],
    nonce: [u8; 12],
    data: &[u8],
    aad: &[u8],
) {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("aead seal: key length is always 32");
    dst[..data.len()].copy_from_slice(data);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut dst[..data.len()])
        .expect("aead seal");
    dst[data.len()..data.len() + 16].copy_from_slice(tag.as_slice());
}

/// ChaCha20-Poly1305 open (ciphertext and tag combined in `src`).
/// Writes plaintext into `dst` (must be at least `src.len() - 16` bytes;
/// a longer `dst` is fine — only the first `src.len() - 16` bytes are
/// written). Returns `Err(())` on a `src` shorter than the tag — `dst`
/// untouched — or on tag mismatch, in which case `dst[..ct_len]` holds
/// the *ciphertext* copy (the detached-tag check runs before the
/// keystream is applied): Err output is unspecified — not plaintext,
/// not the prior contents — and callers must not read it. The caller
/// maps it to `WireGuardError::InvalidAeadTag`. Drop-in for what
/// upstream called `ring::aead::LessSafeKey::open_in_place` over a copy
/// of the input.
#[inline]
pub(crate) fn aead_chacha20_open_inner(
    dst: &mut [u8],
    key: &[u8],
    nonce: [u8; 12],
    src: &[u8],
    aad: &[u8],
) -> Result<(), ()> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("aead open: key length is always 32");
    // src = ciphertext || tag (16 bytes). Copy the ciphertext half into
    // dst and decrypt it in place with the tag detached — one copy, no
    // per-packet `to_vec()` allocation (PATCH(16)). On tag mismatch the
    // copy stays encrypted in dst: Err output is unspecified (see the
    // doc comment), never plaintext.
    let ct_len = src.len().checked_sub(16).ok_or(())?;
    let (ct, tag) = src.split_at(ct_len);
    dst[..ct_len].copy_from_slice(ct);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            aad,
            &mut dst[..ct_len],
            chacha20poly1305::Tag::from_slice(tag),
        )
        .map_err(|_| ())?;
    Ok(())
}

/// `wireguard-boring`: per-session AEAD contexts over BoringSSL.
///
/// The RustCrypto fallback constructs `ChaCha20Poly1305` from the raw
/// session key *per packet* and, under the workspace `opt-level = "z"`
/// release profile, runs the software-scalar chacha20 core (the NEON
/// backend is `chacha20_force_neon`-gated and off by default) — measured
/// ~300–400 MB/s on aarch64. BoringSSL's `EVP_AEAD` does its key
/// schedule once and runs NEON assembly regardless of opt-level
/// (~1.6–2.4 GB/s). `Session` caches one `SessionAead` per direction,
/// so the data path keeps a ready cipher instead of raw key bytes.
#[cfg(feature = "wireguard-boring")]
pub(crate) mod boring_ctx {
    use boring::aead::{AeadCtx, Algorithm};

    /// A session-direction AEAD context: the key schedule built once at
    /// `Session::new`, then reused for every packet in that direction.
    pub(crate) struct SessionAead(AeadCtx);

    impl SessionAead {
        pub(crate) fn new(key: &[u8; 32]) -> Self {
            Self(
                AeadCtx::new_default_tag(&Algorithm::chacha20_poly1305(), key)
                    .expect("ChaCha20-Poly1305 key is always 32 bytes"),
            )
        }

        /// Encrypt `buf` in place; return the 16-byte Poly1305 tag.
        /// `nonce` is the pre-built 12-byte WG nonce (bytes `0..4` zero,
        /// `4..12` little-endian counter).
        pub(crate) fn seal(&self, nonce: [u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
            let mut tag = [0u8; 16];
            let written = self
                .0
                .seal_in_place(&nonce, buf, &mut tag, aad)
                .expect("session seal never fails on a 12-byte nonce");
            // BoringSSL reports the tag prefix it actually wrote — a
            // short write would silently ship zero-padded tag bytes. A
            // release-mode `assert_eq!` too: one usize compare per packet
            // is free, and a wrong tag length is a hard invariant break,
            // not a debug-only nicety.
            assert_eq!(written.len(), 16);
            tag
        }

        /// Verify the tag and decrypt `ct_and_tag` (ciphertext || 16-byte
        /// tag) into `dst`, which must be at least `ct_and_tag.len() - 16`
        /// bytes. Returns the plaintext slice on success. Same one-copy
        /// shape as the RustCrypto path — BoringSSL opens in place, so the
        /// ciphertext lands in `dst` first.
        pub(crate) fn open<'a>(
            &self,
            nonce: [u8; 12],
            aad: &[u8],
            dst: &'a mut [u8],
            ct_and_tag: &[u8],
        ) -> Result<&'a mut [u8], ()> {
            let ct_len = ct_and_tag.len().checked_sub(16).ok_or(())?;
            let (ct, tag) = ct_and_tag.split_at(ct_len);
            dst[..ct_len].copy_from_slice(ct);
            self.0
                .open_in_place(&nonce, &mut dst[..ct_len], tag, aad)
                .map(|_| &mut dst[..ct_len])
                .map_err(|_| ())
        }

        /// Verify `tag` and decrypt `ct` where it stands — the two are
        /// disjoint slices (typically the payload‖tag halves of one
        /// datagram), so unlike `open` there is no ciphertext copy at
        /// all. PATCH(17): `Session::receive_packet_data_in_place` opens
        /// the wire datagram inside the caller's receive buffer itself.
        pub(crate) fn open_detached(
            &self,
            nonce: [u8; 12],
            aad: &[u8],
            ct: &mut [u8],
            tag: &[u8],
        ) -> Result<(), ()> {
            self.0.open_in_place(&nonce, ct, tag, aad).map_err(|_| ())
        }
    }
}

/// Session-layer AEAD seal: data path, in place (no extra plaintext copy).
/// Used by `Session::format_packet_data` where ciphertext is written directly
/// into the caller's output buffer. `nonce_bytes` is the pre-built 12-byte
/// nonce (bytes `0..4` zero, `4..12` little-endian counter).
/// Returns the Poly1305 tag.
#[cfg(feature = "wireguard-boring")]
#[inline]
pub(crate) fn session_seal_in_place(
    aead: &boring_ctx::SessionAead,
    nonce_bytes: [u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> [u8; 16] {
    aead.seal(nonce_bytes, aad, buffer)
}

/// Session-layer AEAD open: data path.
/// `ciphertext_and_tag` is the ciphertext followed by the 16-byte Poly1305
/// tag; `dst` must be at least `ciphertext_and_tag.len() - 16` bytes (the
/// plaintext size — a longer `dst` is fine). Returns a slice into `dst`
/// holding the plaintext on success.
#[cfg(feature = "wireguard-boring")]
#[inline]
pub(crate) fn session_open_in_place<'a>(
    aead: &boring_ctx::SessionAead,
    nonce_bytes: [u8; 12],
    aad: &[u8],
    dst: &'a mut [u8],
    ciphertext_and_tag: &[u8],
) -> Result<&'a mut [u8], ()> {
    aead.open(nonce_bytes, aad, dst, ciphertext_and_tag)
}

/// Session-layer AEAD open, *fully* in place (PATCH(17)): `buf` holds
/// `ciphertext‖tag` — the wire datagram's own payload region — and the
/// plaintext replaces the ciphertext where it stands. No `dst`, no
/// copy: the receive buffer becomes the plaintext buffer. Returns the
/// plaintext length (`buf.len() - 16`).
#[cfg(feature = "wireguard-boring")]
#[inline]
pub(crate) fn session_decrypt_in_place(
    aead: &boring_ctx::SessionAead,
    nonce_bytes: [u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<usize, ()> {
    let ct_len = buf.len().checked_sub(16).ok_or(())?;
    let (ct, tag) = buf.split_at_mut(ct_len);
    aead.open_detached(nonce_bytes, aad, ct, tag)?;
    Ok(ct_len)
}

/// Session-layer AEAD seal: data path, in place (no extra plaintext copy).
/// Used by `Session::format_packet_data` where ciphertext is written directly
/// into the caller's output buffer. `nonce_bytes` is the pre-built 12-byte
/// nonce (bytes `0..4` zero, `4..12` little-endian counter).
/// Returns the Poly1305 tag.
#[cfg(not(feature = "wireguard-boring"))]
#[inline]
pub(crate) fn session_seal_in_place(
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> [u8; 16] {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("session seal: key length is 32");
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), aad, buffer)
        .expect("session seal");
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

/// Session-layer AEAD open: data path, in place.
/// `ciphertext_and_tag` is the ciphertext followed by the 16-byte Poly1305
/// tag; `dst` must be at least `ciphertext_and_tag.len() - 16` bytes (the
/// plaintext size — a longer `dst` is fine). Returns a slice into `dst`
/// holding the plaintext on success.
#[cfg(not(feature = "wireguard-boring"))]
#[inline]
pub(crate) fn session_open_in_place<'a>(
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    aad: &[u8],
    dst: &'a mut [u8],
    ciphertext_and_tag: &[u8],
) -> Result<&'a mut [u8], ()> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("session open: key length is 32");
    let ct_len = ciphertext_and_tag.len();
    // src = ciphertext || tag (16 bytes). decrypt_in_place_detached verifies
    // the tag and leaves the plaintext in place — the right API for a fixed
    // `&mut [u8]` (decrypt_in_place wants a growable Buffer).
    if ct_len < 16 {
        return Err(());
    }
    let (ct, tag) = ciphertext_and_tag.split_at(ct_len - 16);
    dst[..ct_len - 16].copy_from_slice(ct);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce_bytes),
            aad,
            &mut dst[..ct_len - 16],
            chacha20poly1305::Tag::from_slice(tag),
        )
        .map_err(|_| ())?;
    Ok(&mut dst[..ct_len - 16])
}

/// Session-layer AEAD open, *fully* in place (PATCH(17)): `buf` holds
/// `ciphertext‖tag` — the wire datagram's own payload region — and the
/// plaintext replaces the ciphertext where it stands. No `dst`, no
/// copy: the receive buffer becomes the plaintext buffer. Returns the
/// plaintext length (`buf.len() - 16`).
#[cfg(not(feature = "wireguard-boring"))]
#[inline]
pub(crate) fn session_decrypt_in_place(
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<usize, ()> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("session open: key length is 32");
    let ct_len = buf.len().checked_sub(16).ok_or(())?;
    let (ct, tag) = buf.split_at_mut(ct_len);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce_bytes),
            aad,
            ct,
            chacha20poly1305::Tag::from_slice(tag),
        )
        .map_err(|_| ())?;
    Ok(ct_len)
}

/// Constant-time byte-slice equality, replacing what upstream called
/// `ring::constant_time::verify_slices_are_equal`.
/// Returns `Ok(())` if equal, `Err(())` if different or of unequal length.
///
/// Uses `subtle::ConstantTimeEq` — a hand-rolled XOR fold is one
/// optimizer pass away from becoming variable-time; the vetted primitive
/// is already in the tree via `x25519-dalek`.
// SAFETY NOTE: every callsite compares fixed-length values (16-byte MACs,
// 32-byte keys), so the length pre-check is not a timing oracle there —
// but never feed variable-length inputs through this function.
#[inline]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> Result<(), ()> {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return Err(());
    }
    if a.ct_eq(b).into() {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    //! Independent crypto vectors for the ring-replacement facade (spec §7.1).
    //! These must keep passing across vendor bumps: they pin the exact bytes
    //! the patched `noise/` code produces.

    use super::*;

    /// RFC 7539 §A.5 ChaCha20-Poly1305 vector, fed through the facade — the
    /// same assertion boringtun's `chacha20_seal_rfc7530_test_vector` makes on
    /// the now-delegating `aead_chacha20_seal_inner`. Byte-identical output
    /// proves the ring substitution is exact.
    #[test]
    fn chacha20_seal_rfc7530_vector() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let mut buffer = vec![0; plaintext.len() + 16];

        aead_chacha20_seal_inner(&mut buffer, &key, nonce, plaintext, &aad);

        const EXPECTED_CIPHERTEXT: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        const EXPECTED_TAG: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        assert_eq!(buffer[..plaintext.len()], EXPECTED_CIPHERTEXT);
        assert_eq!(buffer[plaintext.len()..], EXPECTED_TAG);
    }

    /// Sealing an empty plaintext with counter=1 in nonce bytes 4..12 must
    /// differ from counter=0 — proves the counter lands in the WG-specified
    /// nonce position.
    #[test]
    fn nonce_counter_placement_le_bytes_4_to_12() {
        let mut dst = vec![0u8; 16]; // empty plaintext + 16-byte tag
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&1u64.to_le_bytes());
        aead_chacha20_seal_inner(&mut dst, &[0u8; 32], nonce, &[], &[]);

        let mut dst0 = vec![0u8; 16];
        aead_chacha20_seal_inner(&mut dst0, &[0u8; 32], [0u8; 12], &[], &[]);

        assert_ne!(
            dst, dst0,
            "counter=1 must produce different ciphertext than counter=0"
        );
    }

    /// Seal/open round-trip on the same key+nonce, and tag-mismatch rejection.
    #[test]
    fn seal_then_open_round_trip() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let aad = b"aad";
        let plaintext = b"wireguard";

        let mut sealed = vec![0u8; plaintext.len() + 16];
        aead_chacha20_seal_inner(&mut sealed, &key, nonce, plaintext, aad);

        let mut opened = vec![0u8; plaintext.len()];
        aead_chacha20_open_inner(&mut opened, &key, nonce, &sealed, aad)
            .expect("must open what was sealed");
        assert_eq!(&opened, plaintext);

        let mut wrong = vec![0u8; plaintext.len()];
        assert!(
            aead_chacha20_open_inner(&mut wrong, &key, nonce, &sealed, b"other").is_err(),
            "wrong AAD must fail tag verification"
        );
    }

    /// The de-`to_vec` `aead_chacha20_open_inner` keeps the exact contract:
    /// plaintext lands in `dst`, a `dst` longer than the plaintext leaves
    /// its tail untouched, a short `src` (no room for the tag) errors,
    /// and a flipped tag byte errors without writing plaintext.
    #[test]
    fn open_inner_contract_after_detached_tag_rewrite() {
        let key = [0x11u8; 32];
        let nonce = [0u8; 12];
        let aad = b"ad";
        let plaintext = b"hello wireguard";

        let mut sealed = vec![0u8; plaintext.len() + 16];
        aead_chacha20_seal_inner(&mut sealed, &key, nonce, plaintext, aad);

        // Longer dst: only the first plaintext.len() bytes are written.
        let mut dst = vec![0xAAu8; plaintext.len() + 8];
        aead_chacha20_open_inner(&mut dst, &key, nonce, &sealed, aad).unwrap();
        assert_eq!(&dst[..plaintext.len()], plaintext.as_slice());
        assert!(
            dst[plaintext.len()..].iter().all(|&b| b == 0xAA),
            "dst tail beyond the plaintext must be untouched"
        );

        // A tag-only src (empty plaintext — the handshake's
        // `encrypted_nothing` shape) still verifies, into an empty dst.
        let mut sealed_empty = vec![0u8; 16];
        aead_chacha20_seal_inner(&mut sealed_empty, &key, nonce, &[], aad);
        aead_chacha20_open_inner(&mut [], &key, nonce, &sealed_empty, aad).unwrap();

        // src shorter than the tag errors rather than panicking.
        assert!(aead_chacha20_open_inner(&mut dst, &key, nonce, &sealed[..8], aad).is_err());

        // Tag mismatch errors; dst then holds the ciphertext half that
        // was copied in before the check failed — the detached-tag path
        // verifies the MAC before applying the keystream, so Err output
        // is ciphertext, not plaintext and not dst's prior contents
        // (callers treat Err as "output unspecified").
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(aead_chacha20_open_inner(&mut dst, &key, nonce, &bad, aad).is_err());
    }

    /// The BoringSSL session context round-trips and rejects a wrong tag —
    /// and the same bytes a RustCrypto seal produced open under BoringSSL
    /// (the two backends are the same primitive on the wire).
    #[cfg(feature = "wireguard-boring")]
    #[test]
    fn boring_session_seal_open_round_trip() {
        use super::boring_ctx::SessionAead;
        let key = [7u8; 32];
        let aead = SessionAead::new(&key);
        let nonce = [3u8; 12];
        let pt = b"wireguard session data";

        let mut buf = pt.to_vec();
        let tag = aead.seal(nonce, b"aad", &mut buf);
        let mut ct_and_tag = buf.clone();
        ct_and_tag.extend_from_slice(&tag);

        let mut dst = vec![0u8; pt.len()];
        assert_eq!(
            aead.open(nonce, b"aad", &mut dst, &ct_and_tag).unwrap(),
            pt.as_slice()
        );

        // Wrong AAD must fail tag verification.
        let mut dst2 = vec![0u8; pt.len()];
        assert!(aead.open(nonce, b"other", &mut dst2, &ct_and_tag).is_err());

        // Cross-backend: RustCrypto-sealed bytes open under BoringSSL.
        let mut rc_sealed = vec![0u8; pt.len() + 16];
        aead_chacha20_seal_inner(&mut rc_sealed, &key, nonce, pt, b"aad");
        let mut dst3 = vec![0u8; pt.len()];
        assert_eq!(
            aead.open(nonce, b"aad", &mut dst3, &rc_sealed).unwrap(),
            pt.as_slice()
        );

        // Reverse leg: the BoringSSL seal is byte-identical to the
        // RustCrypto seal on the same key/nonce/aad/plaintext — and
        // therefore opens under `aead_chacha20_open_inner` too.
        assert_eq!(
            ct_and_tag, rc_sealed,
            "boring and RustCrypto seals must produce identical bytes"
        );
        let mut dst4 = vec![0u8; pt.len()];
        aead_chacha20_open_inner(&mut dst4, &key, nonce, &ct_and_tag, b"aad").unwrap();
        assert_eq!(dst4, pt.as_slice());
    }

    /// Session-path known-answer inputs: one fixed key, the WG nonce for
    /// counter `0x0102030405060708` (bytes `0..4` zero, `4..12`
    /// little-endian — the exact layout `Session::format_packet_data`
    /// builds) and one fixed plaintext under the session path's empty
    /// aad. [`SESSION_KAT_CT_TAG`] is the `ct‖tag` the RustCrypto path
    /// produced for them, generated once and pinned here. The assertion
    /// runs under BOTH backend builds — under `wireguard-boring`,
    /// reproducing these exact bytes seals the nonce/counter encoding
    /// seam between `encrypt_in_place_detached` and BoringSSL's
    /// `AeadCtx::seal_in_place` (a `to_be_bytes`/layout slip would print
    /// different ciphertext, not a different error).
    const SESSION_KAT_KEY: [u8; 32] = [
        0x1c, 0x92, 0x40, 0xa5, 0xfb, 0x55, 0xd0, 0xaf, 0x31, 0xf7, 0x5e, 0xad, 0x3c, 0xcb, 0x62,
        0xbd, 0xf6, 0xa7, 0xc0, 0xcf, 0x8c, 0x0b, 0x4a, 0x35, 0xf1, 0x2e, 0x60, 0x11, 0xa6, 0x37,
        0x4b, 0x6e,
    ];
    const SESSION_KAT_NONCE: [u8; 12] = [0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1];
    const SESSION_KAT_PT: &[u8] = b"wireguard session data known-answer";
    const SESSION_KAT_CT_TAG: [u8; 51] = [
        0x9d, 0xe5, 0x71, 0x6c, 0xbc, 0x89, 0x67, 0x78, 0xc5, 0xe2, 0x42, 0xb2, 0xcc, 0x22, 0x06,
        0xef, 0x75, 0xb9, 0x49, 0xbc, 0x3e, 0x70, 0x20, 0x53, 0x3c, 0xc5, 0xcf, 0x8e, 0x14, 0xe1,
        0xda, 0x7c, 0xb6, 0x43, 0xb7, 0x84, 0xc9, 0x12, 0xec, 0xd9, 0x0a, 0x41, 0x7a, 0x3f, 0x85,
        0x0c, 0x0f, 0x92, 0x5b, 0xbd, 0xe2,
    ];

    /// RustCrypto session backend: seal must reproduce the pinned
    /// `ct‖tag`, and open must round-trip it.
    #[cfg(not(feature = "wireguard-boring"))]
    #[test]
    fn session_seal_open_known_answer() {
        let mut buf = SESSION_KAT_PT.to_vec();
        let tag = session_seal_in_place(&SESSION_KAT_KEY, SESSION_KAT_NONCE, &[], &mut buf);
        buf.extend_from_slice(&tag);
        assert_eq!(
            buf.as_slice(),
            SESSION_KAT_CT_TAG,
            "session seal must reproduce the pinned ct‖tag bytes"
        );

        let mut dst = vec![0u8; SESSION_KAT_PT.len()];
        let pt = session_open_in_place(&SESSION_KAT_KEY, SESSION_KAT_NONCE, &[], &mut dst, &buf)
            .expect("the pinned vector opens");
        assert_eq!(pt, SESSION_KAT_PT);
    }

    /// BoringSSL session backend: byte-identical output on the same
    /// inputs is the whole point of the swap — this is the leg that pins
    /// the nonce/counter encoding seam (see [`SESSION_KAT_CT_TAG`]).
    #[cfg(feature = "wireguard-boring")]
    #[test]
    fn session_seal_open_known_answer() {
        let aead = boring_ctx::SessionAead::new(&SESSION_KAT_KEY);
        let mut buf = SESSION_KAT_PT.to_vec();
        let tag = session_seal_in_place(&aead, SESSION_KAT_NONCE, &[], &mut buf);
        buf.extend_from_slice(&tag);
        assert_eq!(
            buf.as_slice(),
            SESSION_KAT_CT_TAG,
            "boring session seal must reproduce the pinned ct‖tag bytes"
        );

        let mut dst = vec![0u8; SESSION_KAT_PT.len()];
        let pt = session_open_in_place(&aead, SESSION_KAT_NONCE, &[], &mut dst, &buf)
            .expect("the pinned vector opens");
        assert_eq!(pt, SESSION_KAT_PT);
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"hello", b"hello").is_ok());
        assert!(constant_time_eq(b"hello", b"world").is_err());
        assert!(constant_time_eq(b"hello", b"hell").is_err()); // different length
        assert!(constant_time_eq(&[], &[]).is_ok());
    }
}
