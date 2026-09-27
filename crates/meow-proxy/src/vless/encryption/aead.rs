//! Record-layer AEAD, BLAKE3 key derivation, framing helpers, and padding —
//! a direct port of the shared pieces of Xray/mihomo `encryption/common.go`.

use std::time::Duration;

use aes::Aes256;
use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use ctr::cipher::KeyIvInit;

/// AES-256 in CTR mode with a 128-bit big-endian counter — matches Go's
/// `cipher.NewCTR(aes.NewCipher(k), iv)`.
pub(crate) type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// X25519 public key / shared-secret length.
pub(crate) const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key (public key) length.
pub(crate) const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub(crate) const MLKEM768_CT_LEN: usize = 1088;
/// AEAD tag length (both AES-256-GCM and ChaCha20-Poly1305).
pub(crate) const TAG_LEN: usize = 16;

/// All-`0xFF` nonce used as an explicit, counter-independent nonce for the
/// handshake's fixed-position seals (`Seal(..., MaxNonce, ...)`).
const MAX_NONCE: [u8; 12] = [0xFF; 12];

/// BLAKE3 keyed derivation with an arbitrary-bytes context.
///
/// Go calls `blake3.DeriveKey(out, string(ctx), key)` where `ctx` is raw bytes
/// (an IV, a public key, a record, …) reinterpreted as a Go string. The Rust
/// `blake3` crate types the context as `&str` and offers no byte-context form
/// of the DERIVE_KEY_CONTEXT-flagged context hash, so [`blake3_ctx`]
/// reimplements just that one hash over bytes; the material stage then runs
/// through the public hazmat API. Output is byte-for-byte Go-compatible.
fn derive_key(ctx: &[u8], key_material: &[u8]) -> [u8; 32] {
    use blake3::hazmat::HasherExt;
    let context_key = blake3_ctx::context_key(ctx);
    let mut hasher = blake3::Hasher::new_from_context_key(&context_key);
    hasher.update(key_material);
    *hasher.finalize().as_bytes()
}

/// The one piece of `blake3::derive_key` the crate does not expose over bytes:
/// `hash_derive_key_context(context)` — a normal BLAKE3 tree hash of the
/// context, keyed by the IV, with `DERIVE_KEY_CONTEXT` set at every node.
///
/// Mirrors the portable reference (`compress_in_place`/`compress_xof`, the
/// lazy-merge chunk tree): identical output to
/// `blake3::hazmat::hash_derive_key_context` for every valid UTF-8 context,
/// which the tests verify across chunk-boundary lengths.
mod blake3_ctx {
    const CHUNK_LEN: usize = 1024;
    const BLOCK_LEN: usize = 64;
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    const MSG_SCHEDULE: [[usize; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 1 << 1;
    const PARENT: u8 = 1 << 2;
    const ROOT: u8 = 1 << 3;
    const DERIVE_KEY_CONTEXT: u8 = 1 << 5;

    #[inline(always)]
    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn round(state: &mut [u32; 16], msg: &[u32; 16], round: usize) {
        let schedule = MSG_SCHEDULE[round];
        g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
        g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
        g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
        g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);
        g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
        g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
        g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
        g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
    }

    /// `compress_pre` + the `state[i] ^= state[i + 8]` fold — i.e. the crate's
    /// `compress_in_place`, returning the first eight words.
    fn compress(
        cv: [u32; 8],
        block: &[u8; 64],
        counter: u64,
        block_len: u8,
        flags: u8,
    ) -> [u32; 8] {
        let mut words = [0u32; 16];
        for (w, b) in words.iter_mut().zip(block.as_chunks::<4>().0.iter()) {
            *w = u32::from_le_bytes(*b);
        }
        let mut state = [
            cv[0],
            cv[1],
            cv[2],
            cv[3],
            cv[4],
            cv[5],
            cv[6],
            cv[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            counter as u32,
            (counter >> 32) as u32,
            u32::from(block_len),
            u32::from(flags),
        ];
        for r in 0..7 {
            round(&mut state, &words, r);
        }
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = state[i] ^ state[i + 8];
        }
        out
    }

    /// One tree node: its final compress parameters (the crate's `Output`).
    struct Node {
        cv: [u32; 8],
        block: [u8; 64],
        block_len: u8,
        counter: u64,
        flags: u8,
    }

    impl Node {
        fn cv_bytes(&self) -> [u8; 32] {
            words_to_bytes(compress(
                self.cv,
                &self.block,
                self.counter,
                self.block_len,
                self.flags,
            ))
        }
        fn root_bytes(&self) -> [u8; 32] {
            words_to_bytes(compress(
                self.cv,
                &self.block,
                self.counter,
                self.block_len,
                self.flags | ROOT,
            ))
        }
    }

    fn words_to_bytes(w: [u32; 8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (b, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(w.iter()) {
            *b = word.to_le_bytes();
        }
        out
    }

    /// The chunk node for `chunk` at `counter` — all blocks compressed into the
    /// CV except the last, which stays buffered in the node (CHUNK_END flag).
    fn chunk_node(chunk: &[u8], counter: u64) -> Node {
        let mut cv = IV;
        // All but the last block are compressed into the CV; the last stays
        // buffered in the node. An empty chunk is a single zero-length block.
        let blocks = chunk.len().div_ceil(BLOCK_LEN).max(1);
        let buffered = blocks - 1;
        for i in 0..buffered {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(&chunk[i * BLOCK_LEN..(i + 1) * BLOCK_LEN]);
            let flags = DERIVE_KEY_CONTEXT | if i == 0 { CHUNK_START } else { 0 };
            cv = compress(cv, &block, counter, BLOCK_LEN as u8, flags);
        }
        let mut block = [0u8; BLOCK_LEN];
        let tail = &chunk[buffered * BLOCK_LEN..];
        block[..tail.len()].copy_from_slice(tail);
        Node {
            cv,
            block,
            block_len: tail.len() as u8,
            counter,
            flags: DERIVE_KEY_CONTEXT | CHUNK_END | if buffered == 0 { CHUNK_START } else { 0 },
        }
    }

    fn parent_node(left: &[u8; 32], right: &[u8; 32]) -> Node {
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(left);
        block[32..].copy_from_slice(right);
        Node {
            cv: IV,
            block,
            block_len: 64,
            counter: 0,
            flags: DERIVE_KEY_CONTEXT | PARENT,
        }
    }

    /// BLAKE3(`ctx`) with `DERIVE_KEY_CONTEXT` — identical to
    /// `blake3::hazmat::hash_derive_key_context` for any `&str`, but accepts
    /// arbitrary bytes.
    pub(super) fn context_key(ctx: &[u8]) -> [u8; 32] {
        // One chunk per CHUNK_LEN bytes; an empty context still hashes one
        // zero-length chunk (CHUNK_START | CHUNK_END, block_len 0).
        let mut stack: Vec<Node> = Vec::new();
        let chunks: Vec<&[u8]> = if ctx.is_empty() {
            vec![&[]]
        } else {
            ctx.chunks(CHUNK_LEN).collect()
        };
        for (i, chunk) in chunks.iter().enumerate() {
            let mut node = chunk_node(chunk, i as u64);
            // Lazy-merge rule: after the nth chunk, fold subtrees while n is
            // even — same tree shape as the reference implementation.
            let mut total = i as u64 + 1;
            while total.is_multiple_of(2) {
                let left = stack.pop().expect("cv stack has a subtree to merge");
                node = parent_node(&left.cv_bytes(), &node.cv_bytes());
                total >>= 1;
            }
            stack.push(node);
        }
        // Fold the remaining subtree stack right-to-left; the last merge (or
        // the single chunk itself) is the root.
        loop {
            let node = stack.pop().expect("at least one chunk exists");
            match stack.pop() {
                None => return node.root_bytes(),
                Some(left) => {
                    let merged = parent_node(&left.cv_bytes(), &node.cv_bytes());
                    if stack.is_empty() {
                        return merged.root_bytes();
                    }
                    stack.push(merged);
                }
            }
        }
    }
}

/// BLAKE3-256 hash — Go's `blake3.Sum256`.
pub(crate) fn blake3_sum256(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// `NewCTR(key, iv)` — AES-256-CTR keyed by `DeriveKey("VLESS", key)`.
pub(crate) fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Aes256Ctr {
    let k = blake3::derive_key("VLESS", key);
    Aes256Ctr::new((&k).into(), iv.into())
}

/// An AEAD instance with a per-instance auto-incrementing nonce counter,
/// mirroring Go's `encryption.AEAD`.
pub(crate) struct Aead {
    cipher: Cipher,
    nonce: [u8; 12],
}

enum Cipher {
    Aes(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl Aead {
    /// `NewAEAD(ctx, key, useAES)` — derives a 32-byte key via BLAKE3 and
    /// selects AES-256-GCM or ChaCha20-Poly1305.
    pub(crate) fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        let k = derive_key(ctx, key);
        let cipher = if use_aes {
            Cipher::Aes(Box::new(Aes256Gcm::new((&k).into())))
        } else {
            Cipher::Chacha(Box::new(ChaCha20Poly1305::new((&k).into())))
        };
        Self {
            cipher,
            nonce: [0u8; 12],
        }
    }

    /// Pre-increment the big-endian nonce counter (Go's `IncreaseNonce`).
    fn increment_nonce(&mut self) {
        for i in 0..12 {
            let idx = 11 - i;
            self.nonce[idx] = self.nonce[idx].wrapping_add(1);
            if self.nonce[idx] != 0 {
                break;
            }
        }
    }

    /// `true` when the counter sits at the maximum nonce — the record layer
    /// re-keys on the boundary (`bytes.Equal(Nonce, MaxNonce)`).
    pub(crate) fn is_exhausted(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let payload = Payload {
            msg: plaintext,
            aad: ad,
        };
        match &self.cipher {
            Cipher::Aes(c) => c.encrypt(nonce.into(), payload),
            Cipher::Chacha(c) => c.encrypt(nonce.into(), payload),
        }
        .expect("AEAD seal is infallible for valid inputs")
    }

    fn decrypt(&self, nonce: &[u8; 12], ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let payload = Payload { msg: ct, aad: ad };
        match &self.cipher {
            Cipher::Aes(c) => c.decrypt(nonce.into(), payload),
            Cipher::Chacha(c) => c.decrypt(nonce.into(), payload),
        }
    }

    /// Seal with the auto-incrementing counter and no associated data.
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.encrypt(&nonce, plaintext, &[])
    }

    /// Seal with the auto-incrementing counter and associated data (record header).
    pub(crate) fn seal_ad(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.encrypt(&nonce, plaintext, ad)
    }

    /// Seal with the explicit all-`0xFF` nonce (counter untouched).
    ///
    /// Only the server seals at `MaxNonce` (the client reads it via
    /// [`Self::open_max`]), so this is exercised solely by the reference test
    /// server today.
    #[cfg(test)]
    pub(crate) fn seal_max(&self, plaintext: &[u8]) -> Vec<u8> {
        self.encrypt(&MAX_NONCE, plaintext, &[])
    }

    /// Open with the auto-incrementing counter and no associated data.
    pub(crate) fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.decrypt(&nonce, ct, &[])
    }

    /// Open with the auto-incrementing counter and associated data (record header).
    pub(crate) fn open_ad(&mut self, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.decrypt(&nonce, ct, ad)
    }

    /// Open with the explicit all-`0xFF` nonce (counter untouched).
    pub(crate) fn open_max(&self, ct: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.decrypt(&MAX_NONCE, ct, &[])
    }
}

// ─── Length / header framing (`common.go`) ────────────────────────────────────

/// `EncodeLength(l)` — 2-byte big-endian.
pub(crate) fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}

/// `DecodeLength(b)` — 2-byte big-endian.
pub(crate) fn decode_length(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | (b[1] as usize)
}

/// `EncodeHeader(h, l)` — a fake TLS 1.3 application-data record header.
pub(crate) fn encode_header(l: usize) -> [u8; 5] {
    [23, 3, 3, (l >> 8) as u8, l as u8]
}

/// `DecodeHeader(h)` — returns the record body length (17..=16640) or an error
/// for an out-of-range / malformed header. Matches Go byte-for-byte.
pub(crate) fn decode_header(h: &[u8; 5]) -> Result<usize, std::io::Error> {
    let mut l = ((h[3] as usize) << 8) | (h[4] as usize);
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        l = 0;
    }
    // TLS 1.3 max record: 16384 + 256 (RFC 8446 §5.2).
    if !(17..=16640).contains(&l) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("vless-encryption: invalid record header: {h:?}"),
        ));
    }
    Ok(l)
}

// ─── Padding (`ParsePadding` / `CreatPadding`) ────────────────────────────────

/// Upper bound on cumulative padding gaps (ms). Lens are capped by the
/// u16-sized record length field (65553); gaps become `Duration` sleeps
/// between the fragmented client-hello writes in `connect`, so an
/// unbounded provider-supplied value would park a dial for up to
/// ~292 My (issue #648). 60 s is beyond any pacing scheme.
const MAX_PADDING_GAP_MS: i64 = 60_000;

/// Parsed padding schedule: alternating length triples and gap triples.
#[derive(Default, Clone)]
pub(crate) struct Padding {
    lens: Vec<[i64; 3]>,
    gaps: Vec<[i64; 3]>,
}

/// `ParsePadding` — parses a `100-111-1111.75-0-111.50-0-3333` style string.
pub(crate) fn parse_padding(padding: &str) -> Result<Padding, String> {
    let mut out = Padding::default();
    if padding.is_empty() {
        return Ok(out);
    }
    let mut max_len: i64 = 0;
    let mut max_gap: i64 = 0;
    for (i, s) in padding.split('.').enumerate() {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
            return Err(format!("invalid padding length/gap parameter: {s}"));
        }
        let mut y = [0i64; 3];
        for (k, p) in parts.iter().take(3).enumerate() {
            y[k] = p
                .parse::<i64>()
                .map_err(|_| format!("invalid padding number: {p}"))?;
        }
        if i == 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17) {
            return Err("first padding length must not be smaller than 35".into());
        }
        // Reject negative range endpoints — a negative contribution would
        // launder the length cap below, and `rand_between`/`Duration`
        // conversion of a negative endpoint yields a giant `usize`/`u64`
        // (issue #648). The `i64` sums use `checked_add` so two huge
        // endpoints can't wrap `max_len` back under the cap either.
        if y[1] < 0 || y[2] < 0 {
            return Err(format!("negative padding range in: {s}"));
        }
        if i % 2 == 0 {
            out.lens.push(y);
            max_len = max_len
                .checked_add(y[1].max(y[2]))
                .ok_or_else(|| "total padding length overflow".to_string())?;
        } else {
            out.gaps.push(y);
            max_gap = max_gap
                .checked_add(y[1].max(y[2]))
                .ok_or_else(|| "total padding gap overflow".to_string())?;
        }
    }
    if max_len > 18 + 65535 {
        return Err("total padding length must not be larger than 65553".into());
    }
    if max_gap > MAX_PADDING_GAP_MS {
        return Err(format!(
            "total padding gap must not be larger than {MAX_PADDING_GAP_MS} ms"
        ));
    }
    Ok(out)
}

/// `CreatPadding` — samples concrete padding lengths and inter-fragment gaps.
///
/// The exact random values need not match the Go implementation: the padding
/// content is random and its length is signalled to the peer via an encrypted
/// length prefix, so any in-range sample interoperates.
pub(crate) fn create_padding(p: &Padding) -> (usize, Vec<usize>, Vec<Duration>) {
    let (lens_spec, gaps_spec) = if p.lens.is_empty() {
        (vec![[100, 111, 1111], [50, 0, 3333]], vec![[75, 0, 111]])
    } else {
        (p.lens.clone(), p.gaps.clone())
    };

    let mut lens = Vec::with_capacity(lens_spec.len());
    let mut length = 0usize;
    for y in &lens_spec {
        let mut l = 0i64;
        if y[0] >= rand_between(0, 100) {
            l = rand_between(y[1], y[2]);
        }
        lens.push(l as usize);
        length += l as usize;
    }
    let mut gaps = Vec::with_capacity(gaps_spec.len());
    for y in &gaps_spec {
        let mut g = 0i64;
        if y[0] >= rand_between(0, 100) {
            g = rand_between(y[1], y[2]);
        }
        gaps.push(Duration::from_millis(g as u64));
    }
    (length, lens, gaps)
}

/// `crypto.RandBetween(from, to)` — a uniform sample in `[from, to)`
/// (`to == from` yields `from`).
fn rand_between(from: i64, to: i64) -> i64 {
    if to <= from {
        return from;
    }
    let span = (to - from) as u64;
    from + (rand::random::<u64>() % span) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_increments_big_endian_and_wraps() {
        let mut a = Aead::new(b"ctx", b"key", true);
        assert_eq!(a.nonce, [0u8; 12]);
        a.increment_nonce();
        assert_eq!(a.nonce[11], 1);
        // Force a carry.
        a.nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF];
        a.increment_nonce();
        assert_eq!(a.nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
        // Wrap from max to zero.
        a.nonce = MAX_NONCE;
        assert!(a.is_exhausted());
        a.increment_nonce();
        assert_eq!(a.nonce, [0u8; 12]);
    }

    /// The hand-rolled context hash must reproduce `blake3::derive_key`
    /// bit-for-bit — checkable on any valid UTF-8 context, across every
    /// chunk-boundary length and tree depth.
    #[test]
    fn byte_context_derive_matches_str_derive_key() {
        let mut rng_state = 0x9E3779B97F4A7C15u64;
        let mut next = || {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            rng_state
        };
        for len in [
            0usize, 1, 63, 64, 65, 127, 1023, 1024, 1025, 1087, 2047, 2048, 2049, 3000, 4096,
            7168,  // 7 chunks — popcount 3: exercises the final-fold re-push
            15360, // 15 chunks — popcount 4: three re-push iterations
            16645, // VLESS rekey ctx: 5-byte header + a max-size record
            8192,
        ] {
            // Valid UTF-8 by construction: ASCII bytes only.
            let ctx: String = (0..len)
                .map(|_| ((next() % 95) as u8 + 32) as char)
                .collect();
            let material: Vec<u8> = (0..64).map(|_| next() as u8).collect();
            assert_eq!(
                derive_key(ctx.as_bytes(), &material),
                blake3::derive_key(&ctx, &material),
                "context length {len}"
            );
        }
    }

    /// The whole point: contexts that are not UTF-8 (IVs, keys, ciphertext)
    /// must not error or panic — and two different binary contexts derive
    /// different keys.
    #[test]
    fn byte_context_derive_accepts_arbitrary_bytes() {
        let a = derive_key(&[0xFF; 32], b"key");
        let b = derive_key(&[0xFE; 32], b"key");
        assert_ne!(a, b);
        // ~16 KiB of invalid-UTF-8 bytes — exercises the multi-chunk tree.
        let big = vec![0x80u8; 16 * 1024 + 7];
        let _ = derive_key(&big, b"key");
    }

    #[test]
    fn aead_round_trip_both_ciphers() {
        for use_aes in [true, false] {
            let mut enc = Aead::new(b"iv", b"key", use_aes);
            let mut dec = Aead::new(b"iv", b"key", use_aes);
            let ct = enc.seal_ad(b"hello world", b"\x17\x03\x03\x00\x1b");
            let pt = dec.open_ad(&ct, b"\x17\x03\x03\x00\x1b").unwrap();
            assert_eq!(pt, b"hello world");
        }
    }

    #[test]
    fn header_round_trip_and_bounds() {
        let h = encode_header(20);
        assert_eq!(decode_header(&h).unwrap(), 20);
        // Too short / too long / wrong prefix are rejected.
        assert!(decode_header(&encode_header(16)).is_err());
        assert!(decode_header(&[0, 3, 3, 0, 20]).is_err());
    }

    #[test]
    fn parse_padding_rejects_short_first() {
        assert!(parse_padding("10-20-30").is_err());
        assert!(parse_padding("100-111-1111.75-0-111").is_ok());
        assert!(parse_padding("").is_ok());
    }

    #[test]
    fn parse_padding_bounded_against_overflow() {
        // Two i64::MAX lens endpoints would wrap `max_len` back under the
        // cap without `checked_add` (issue #648).
        let huge = format!("100-{m}-{m}.1-0-0.1-{m}-{m}", m = i64::MAX);
        assert!(parse_padding(&huge).is_err());
        // A single over-cap lens value is caught by the existing bound.
        assert!(parse_padding("100-35-999999").is_err());
        // Gaps get their own bound — a giant ms value is a dial-hang.
        assert!(parse_padding("100-111-1111.75-0-99999999").is_err());
        assert!(parse_padding("100-111-1111.75-0-111").is_ok());
    }
}
