//! Snell KDF.
//!
//! Port of opensnell `components/snell/cipher.go`. The Snell-specific KDF is
//! Argon2id with t=3, m=8 KiB, p=1, 32-byte output; the first `key_size`
//! bytes are used as the AEAD key (AES-128-GCM uses 16). The AEAD itself is
//! the crate's BoringSSL one (`crate::aead`).

use argon2::{Algorithm, Argon2, Params, Version};

/// Snell KDF — Argon2id(t=3, m=8 KiB, p=1) → 32 bytes; first `key_size`
/// bytes are the AEAD key.
///
/// The 8 KiB memory and 3 passes mirror the official server's
/// `argon2.IDKey(psk, salt, 3, 8, 1, 32)` call exactly. Mismatching either
/// parameter produces a different key and the AEAD handshake silently fails
/// with "snell v4 invalid frame header".
pub fn snell_kdf(psk: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
    debug_assert!(key_size <= 32, "snell KDF caller asked for >32 B");
    let params = Params::new(8, 3, 1, Some(32)).expect("static snell KDF params are valid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; 32];
    argon2
        .hash_password_into(psk, salt, &mut out)
        .expect("argon2 hash_password_into never fails with valid params + output len 32");
    out.truncate(key_size);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic_for_same_inputs() {
        let psk = b"shared-secret";
        let salt = [7u8; 16];
        let a = snell_kdf(psk, &salt, 16);
        let b = snell_kdf(psk, &salt, 16);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn kdf_differs_on_different_salt() {
        let psk = b"shared-secret";
        let a = snell_kdf(psk, &[0u8; 16], 16);
        let b = snell_kdf(psk, &[1u8; 16], 16);
        assert_ne!(a, b);
    }
}
