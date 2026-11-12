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
/// written). Returns `Err(())` on tag mismatch — the caller maps it to
/// `WireGuardError::InvalidAeadTag`. Drop-in for what upstream called
/// `ring::aead::LessSafeKey::open_in_place` over a copy of the input.
#[inline]
pub(crate) fn aead_chacha20_open_inner(
    dst: &mut [u8],
    key: &[u8],
    nonce: [u8; 12],
    src: &[u8],
    aad: &[u8],
) -> Result<(), ()> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("aead open: key length is always 32");
    // src = ciphertext || tag (16 bytes); decrypt_in_place strips the tag.
    let mut buf = src.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(&nonce), aad, &mut buf)
        .map_err(|_| ())?;
    dst[..buf.len()].copy_from_slice(&buf);
    Ok(())
}

/// Session-layer AEAD seal: data path, in place (no extra plaintext copy).
/// Used by `Session::format_packet_data` where ciphertext is written directly
/// into the caller's output buffer. `nonce_bytes` is the pre-built 12-byte
/// nonce (bytes `0..4` zero, `4..12` little-endian counter).
/// Returns the Poly1305 tag.
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

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"hello", b"hello").is_ok());
        assert!(constant_time_eq(b"hello", b"world").is_err());
        assert!(constant_time_eq(b"hello", b"hell").is_err()); // different length
        assert!(constant_time_eq(&[], &[]).is_ok());
    }
}
