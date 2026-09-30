//! Snell KDF and AEAD helpers.
//!
//! Port of opensnell `components/snell/cipher.go`. The Snell-specific KDF is
//! Argon2id with t=3, m=8 KiB, p=1, 32-byte output; the first `key_size`
//! bytes are used as the AEAD key (AES-128-GCM uses 16).
//!
//! AES-128-GCM itself is BoringSSL's (the library meow-transport already
//! links), not a generic Rust AEAD: the release profile's `opt-level = "z"`
//! leaves generic cipher code ~25× slower than BoringSSL's assembly, and
//! every Snell byte passes through here (issue #659).

use argon2::{Algorithm, Argon2, Params, Version};
use boring::aead::{self, AeadCtx};

/// AES-128-GCM nonce length.
pub const NONCE_LEN: usize = 12;
/// AES-128-GCM tag length.
pub const TAG_LEN: usize = 16;

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

/// Build an AES-128-GCM cipher from a 16-byte key.
pub fn aes_gcm(key: &[u8]) -> Aes128Gcm {
    debug_assert_eq!(key.len(), 16, "snell AEAD requires a 16-byte AES-128 key");
    Aes128Gcm(
        AeadCtx::new_default_tag(&aead::Algorithm::aes_128_gcm(), key)
            .expect("16-byte key is valid for AES-128-GCM"),
    )
}

/// AEAD failure: a tag that does not authenticate, or a sealed buffer too
/// short to hold one.
#[derive(Debug)]
pub struct AeadError;

/// One direction's AES-128-GCM key schedule. The schedule lives behind
/// BoringSSL's context pointer, so this is pointer-sized.
pub struct Aes128Gcm(AeadCtx);

impl Aes128Gcm {
    /// Encrypt `data` in place under `nonce` and `ad`, writing the tag to
    /// `tag` (which must be [`TAG_LEN`] bytes).
    pub fn seal_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        debug_assert_eq!(tag.len(), TAG_LEN);
        self.0
            .seal_in_place(nonce, data, tag, ad)
            .map(|_| ())
            .map_err(|_| AeadError)
    }

    /// Verify `tag` and decrypt `data` in place under `nonce` and `ad`.
    pub fn open_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        self.0
            .open_in_place(nonce, data, tag, ad)
            .map_err(|_| AeadError)
    }

    /// Encrypt `buf` in place with no associated data and append the tag.
    pub fn seal_append(&self, nonce: &[u8; NONCE_LEN], buf: &mut Vec<u8>) -> Result<(), AeadError> {
        let len = buf.len();
        buf.resize(len + TAG_LEN, 0);
        let (data, tag) = buf.split_at_mut(len);
        self.seal_detached(nonce, &[], data, tag)
    }

    /// Verify and strip the trailing tag of `buf`, decrypting the rest in
    /// place with no associated data.
    pub fn open_trailing(
        &self,
        nonce: &[u8; NONCE_LEN],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let len = buf.len().checked_sub(TAG_LEN).ok_or(AeadError)?;
        let (data, tag) = buf.split_at_mut(len);
        self.open_detached(nonce, &[], data, tag)?;
        buf.truncate(len);
        Ok(())
    }
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

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// McGrew–Viega GCM spec test case 4 (AES-128, 60-byte plaintext, AAD):
    /// pins the detached-tag path the v6 record layer uses to the standard,
    /// independently of the round-trip tests that share one implementation.
    #[test]
    fn seal_detached_matches_gcm_spec_test_case_4() {
        let aead = aes_gcm(&unhex("feffe9928665731c6d6a8f9467308308"));
        let nonce: [u8; NONCE_LEN] = unhex("cafebabefacedbaddecaf888").try_into().unwrap();
        let ad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plain = unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d\
             8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let mut data = plain.clone();
        let mut tag = [0u8; TAG_LEN];
        aead.seal_detached(&nonce, &ad, &mut data, &mut tag)
            .unwrap();
        assert_eq!(
            data,
            unhex(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e23\
                 29aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
            )
        );
        assert_eq!(tag.to_vec(), unhex("5bc94fbc3221a5db94fae95ae7121a47"));

        aead.open_detached(&nonce, &ad, &mut data, &tag).unwrap();
        assert_eq!(data, plain);
    }

    /// GCM spec test case 2 (zero key/nonce, one zero block) through the
    /// tag-appending path v3/v4 use.
    #[test]
    fn seal_append_matches_gcm_spec_test_case_2() {
        let aead = aes_gcm(&[0u8; 16]);
        let nonce = [0u8; NONCE_LEN];
        let mut buf = vec![0u8; 16];
        aead.seal_append(&nonce, &mut buf).unwrap();
        assert_eq!(
            buf,
            unhex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
        );

        aead.open_trailing(&nonce, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn open_rejects_tampering_and_short_input() {
        let aead = aes_gcm(&[7u8; 16]);
        let nonce = [1u8; NONCE_LEN];
        let mut buf = b"snell".to_vec();
        aead.seal_append(&nonce, &mut buf).unwrap();

        let mut flipped = buf.clone();
        flipped[0] ^= 1;
        assert!(aead.open_trailing(&nonce, &mut flipped).is_err());
        assert!(aead
            .open_trailing(&[2u8; NONCE_LEN], &mut buf.clone())
            .is_err());
        assert!(aead
            .open_trailing(&nonce, &mut vec![0u8; TAG_LEN - 1])
            .is_err());

        let mut detached = b"snell".to_vec();
        let mut tag = [0u8; TAG_LEN];
        aead.seal_detached(&nonce, b"ad", &mut detached, &mut tag)
            .unwrap();
        assert!(aead
            .open_detached(&nonce, b"other ad", &mut detached.clone(), &tag)
            .is_err());
        aead.open_detached(&nonce, b"ad", &mut detached, &tag)
            .unwrap();
        assert_eq!(detached, b"snell");
    }
}
