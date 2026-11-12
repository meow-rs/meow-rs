# PATCHES — boringtun 0.7.1 → meow-wireguard

Ordered list of every deviation from the upstream tarball
(`boringtun 0.7.1`, cloudflare/boringtun @ v0.7.1, BSD-3-Clause — see
`UPSTREAM` and `LICENSE`). To bump the vendored version: copy the same file
set from the new release, then re-apply the patches below in order. Every
site is also marked in-source with a `PATCH(n)` or `PATCH(kind)` comment.

```
Patch 1 — Rewrite Cargo.toml (deps)
  Remove:  ring, untrusted, socket2, thiserror, jni, nix (target.unix),
           mock_instant, tracing-subscriber, criterion/etherparse dev-deps,
           ip_network, ip_network_table, hex (unused by the vendored modules),
           rand (never needed — see Patch 6)
  Keep/align: aead           "0.5.0-pre.2" -> "0.5"     (unifies with the aead
                                                        0.5.2 that the
                                                        workspace's
                                                        chacha20poly1305 0.10
                                                        already pulls; the
                                                        -pre.2 pin would
                                                        duplicate the crate
                                                        and its types would
                                                        not unify)
              rand_core      "0.6" + getrandom          (kept — see Patch 6)
              x25519-dalek   workspace ("2", features static_secrets +
                                                        reusable_secrets)
              blake2/hmac/chacha20poly1305/parking_lot/tracing/base64
                             workspace versions
              portable-atomic "1" + fallback
              libc           "0.2" (needed by Patch 9)
  Add:     [lints] workspace = true,
           feature `mock-instant = []` (empty — see Patch 8),
           subtle "2" (crypto.rs facade dep — see Patch 13 note on
           constant_time_eq), hmac (see Patch 13), and the publishable-
           crate metadata (description/license/repository/homepage/
           readme) — the crate is published under the `meow-` name like
           meow-anytls/meow-lwip so meow-proxy's optional `wireguard`
           feature resolves from crates.io; do not add `publish=false`

Patch 2 — Replace ring AEAD in handshake.rs
  File: src/noise/handshake.rs
  Remove: use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305}
  Change: aead_chacha20_seal_inner body -> calls
          crate::crypto::aead_chacha20_seal_inner (signature unchanged, so
          aead_chacha20_seal and all callers are untouched)
          aead_chacha20_open_inner body -> calls
          crate::crypto::aead_chacha20_open_inner; return type changes
          Result<(), ring::error::Unspecified> -> Result<(), ()>
          (caller maps to WireGuardError::InvalidAeadTag either way)

Patch 3 — Replace ring constant_time in handshake.rs
  File: src/noise/handshake.rs (in receive_handshake_initialization)
  Remove: ring::constant_time::verify_slices_are_equal(
              self.params.peer_static_public.as_bytes(),
              &peer_static_public_decrypted)
          .map_err(|_| WireGuardError::WrongKey)?;
  Add:    crate::crypto::constant_time_eq(...) with identical arguments

Patch 4 — Replace ring AEAD in session.rs
  File: src/noise/session.rs
  Remove: use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305}
  Struct: receiver: LessSafeKey -> receiver_key: [u8; 32]
          sender:   LessSafeKey -> sender_key:   [u8; 32]
  new():  store the key bytes directly (no UnboundKey construction)
  format_packet_data(): nonce[4..12] = counter LE; call
          crate::crypto::session_seal_in_place(&self.sender_key, nonce, &[],
          &mut data[..src.len()]) then append the returned tag at
          data[src.len()..src.len()+AEAD_SIZE]
  receive_packet_data(): same nonce layout; call
          crate::crypto::session_open_in_place(&self.receiver_key, nonce, &[],
          dst, packet.encrypted_encapsulated_packet)
          .map_err(|_| WireGuardError::InvalidAeadTag)?

Patch 5 — Replace ring constant_time in rate_limiter.rs
  File: src/noise/rate_limiter.rs
  Remove: use ring::constant_time::verify_slices_are_equal
  Change: BOTH callsites (mac1 check and mac2 check in verify_packet) ->
          crate::crypto::constant_time_eq

Patch 6 — rand_core: NOT APPLIED (spec deviation, deliberate)
  Upstream's `use rand_core::{OsRng, RngCore}` lines are kept VERBATIM in
  handshake.rs, rate_limiter.rs and mod.rs (tests). Do not rewrite them to
  `rand::rngs::OsRng`/`rand::RngCore`: x25519-dalek 2.x is generic over
  rand_core 0.6's RngCore+CryptoRng (ReusableSecret/StaticSecret::
  random_from_rng(OsRng)), while the workspace `rand` 0.9 implements
  rand_core 0.9 traits — the substitution does not compile. `rand_core
  0.6.4` is already in the workspace lockfile (x25519-dalek's own dep), so
  keeping the pin costs nothing.

Patch 7 — Rewrite lib.rs
  Remove: device/ffi/jni module declarations and their feature gates.
  Keep:   pub mod noise; pub mod x25519 (x25519_dalek re-export);
          pub(crate) mod serialization;
          pub(crate) mod sleepyinstant under
          #[cfg(not(feature = "mock-instant"))].
  Add:    pub(crate) mod crypto;  (the ring-replacement facade)
          #[cfg(feature = "mock-instant")] pub(crate) mod mock_instant;
          pub use noise::{Tunn, TunnResult, errors::WireGuardError};
          (root re-exports used by the Phase-2 adapter + tests)

Patch 8 — mock_instant -> in-crate shim
  Upstream gates `use mock_instant::Instant` / `mock_instant::MockClock` on
  the `mock-instant` feature. The mock_instant crate is not vendored; the
  feature is declared EMPTY and src/mock_instant.rs provides the same
  surface (Instant::now/duration_since/elapsed + test-only MockClock::
  advance) as a process-global offset over std::time::Instant.
  Import path changes (mechanical): mock_instant:: -> crate::mock_instant::
  in noise/handshake.rs, noise/rate_limiter.rs, noise/timers.rs and
  noise/mod.rs (tests).

Patch 9 — sleepyinstant/unix.rs: nix -> libc
  Upstream called nix::{time::clock_gettime, sys::time::TimeSpec}; `nix` is
  eliminated with the device module. unix.rs is rewritten to call
  libc::clock_gettime directly — identical CLOCK_BOOTTIME (Linux family) /
  CLOCK_MONOTONIC (macOS/iOS/tvOS/FreeBSD) selection and identical
  duration math. sleepyinstant/mod.rs: `#![forbid(unsafe_code)]` ->
  `#![deny(unsafe_code)]` and unix.rs carries `#![allow(unsafe_code)]`
  for the single audited FFI callsite. windows.rs is verbatim.

Patch 10 — serialization.rs: base64 0.13-era API -> base64 0.22
  `base64::decode(s)` (removed free function) ->
  `base64::engine::general_purpose::STANDARD.decode(s)` via the Engine
  trait. `#[allow(dead_code)]` added on KeyBytes — its only upstream users
  were the device/ffi key parsers we do not vendor.

Patch 11 — noise/mod.rs small fixes
  * `use std::convert::{TryFrom, TryInto}` deleted — both are in the
    edition-2021 prelude (the explicit import is a redundant-import
    warning on the workspace toolchain; upstream targets edition 2018).
  * test helper create_ipv4_udp_packet(): etherparse::PacketBuilder ->
    a literal byte array of the same packet (etherparse is a dev-dep we
    do not vendor). The tunnel only inspects the version nibble, total
    length and source address, so the hand-built packet is equivalent.

Patch 12 — lint-only mechanical fixes (workspace clippy set; no behavior
            changes anywhere in this patch)
  * noise/mod.rs:
    - four packet-view structs + the Packet enum: `derive(Debug)` ->
      `derive(Debug, Clone, Copy)` — all fields are Copy; upstream passes
      them by value without consuming (needless_pass_by_value).
    - `parse_incoming_packet` return type `Packet` -> `Packet<'_>`
      (rustc mismatched_lifetime_syntaxes).
    - tests: six `let x = if let Pat(v) = y { v } else { unreachable!() }`
      -> `let Pat(v) = y else { unreachable!() }` (manual_let_else); `;`
      added after tail call in handshake_no_resp_rekey_timeout
      (semicolon_if_nothing_returned).
  * noise/handshake.rs:
    - `;` added after the `aead_chacha20_seal_inner` call in
      aead_chacha20_seal and after set_static_private
      (semicolon_if_nothing_returned).
    - receive_cookie_reply: `match { Some(mac) => mac, None => return Err }`
      -> `let Some(mac1) = ... else` (manual_let_else).
    - format_handshake_response: `let (a, b, c, d) = match state { Pat{..}
      => (a,b,c,d), _ => panic!() }` -> `let Pat{..} = state else {
      panic!() }` (manual_let_else; field shorthand `mut x` for the two
      rebound fields).
    - `#[allow(clippy::unnecessary_wraps, reason = ...)]` on
      append_mac1_and_mac2 — its always-Ok Result signature is kept
      verbatim so both `?`/`Ok` callers stay identical to upstream.
    - test: `eprintln!(".. {:?}", x)` -> `{x:?}` inline fmt
      (uninlined_format_args).
  * noise/session.rs:
    - will_accept: `if !check_bit(c) { Ok } else { Err }` -> swapped arms
      (if_not_else).
    - mark_did_receive: `for c in self.bitmap.iter_mut() { *c = 0 }` ->
      `self.bitmap.fill(0)` (explicit_iter_loop + manual_slice_fill);
      `i % WORD_SIZE != 0` -> `!i.is_multiple_of(WORD_SIZE)`
      (manual_is_multiple_of).
    - format_packet_data: drop redundant `as u64` (unnecessary_cast).
  * noise/rate_limiter.rs:
    - doc comment: blank `///` line added between the `*` list and the
      following paragraph (doc_lazy_continuation).
    - verify_packet: `match src_addr { ... }` -> `let Some(addr) = ... else`
      (manual_let_else).
Patch 13 — noise/mod.rs: DATA_OVERHEAD_SZ private -> pub + facade deps
  * `const DATA_OVERHEAD_SZ` -> `pub const DATA_OVERHEAD_SZ` and
    `pub use noise::{..., DATA_OVERHEAD_SZ}` in lib.rs: the smoltcp pump
    (meow-proxy) sizes its encapsulation work buffer against the same
    constant instead of a magic 32 that could drift on a vendor bump.
  * crypto.rs `constant_time_eq` uses `subtle::ConstantTimeEq` (added to
    Cargo.toml in Patch 1) — a hand-rolled XOR fold is one optimizer pass
    away from variable-time; subtle is already in the tree via
    x25519-dalek. Keep the length pre-check + the SAFETY NOTE.
  * crypto.rs `aead_chacha20_open_inner` writes `dst[..buf.len()]`
    (caller buffers may be larger than the plaintext — documented).

Patch 14 — noise/mod.rs tests: serialize the process-global mock clock
  Patch 8's MockClock is a single global offset shared by every test in
  the process. Upstream's `new_handshake_after_two_mins` advances +120s,
  which can land inside `handshake_no_resp_rekey_timeout`'s in-flight
  `InitSent` window and push it past REKEY_ATTEMPT_TIME (90s) — a ~1-in-5
  flake under `cargo test` threads; cargo-nextest's per-test processes
  cannot collide. `static TIMER_CLOCK_LOCK` (parking_lot::Mutex) is held
  for the whole body of every test that advances the clock or asserts on
  a clock-sensitive intermediate state.
  Also adds `forced_handshake_initiation_recovers_expired_session` —
  pins the Expired -> InitSent recovery contract the meow-proxy
  wireguard pump's tick_timers relies on. It drives the Expired state
  via `handshake.set_expired()` (pub(crate), reachable from the test
  module) instead of a real 90s+ advance precisely to avoid widening
  that race surface; it still takes the lock for its final
  clock-sensitive timer assert.
```

Notes on what did NOT need patching

* `receive_cookie_reply` (handshake.rs) already uses
  `chacha20poly1305::XChaCha20Poly1305` + `aead::{Aead, Payload}` — no ring —
  so it is byte-verbatim. The `aead` dep is kept for exactly these imports
  (here and rate_limiter.rs's `aead::generic_array::GenericArray`).
* `b2s_hmac`/`b2s_hmac2` use `hmac::SimpleHmac<Blake2s256>` (RFC-2401 HMAC);
  `b2s_keyed_mac_16*` use `Blake2sMac` (keyed BLAKE2s). Neither touches ring;
  do not "simplify" them into each other.
* noise/errors.rs and sleepyinstant/windows.rs are byte-identical to
  upstream.
* `parse_incoming_packet` (noise/mod.rs) keeps upstream's strict check
  verbatim: bytes 0..4 are read as one LE u32, so any non-zero reserved
  byte fails type matching. Cloudflare WARP-style peers stamp non-zero
  identifiers there — the don't-care receive semantics lives in the
  caller instead (meow-proxy's pump zeroes bytes 1..4 of every inbound
  datagram before `decapsulate`, in `decapsulate_wire`). Do NOT loosen
  this check inside the crate, and do not "fix" the parser on a vendor
  bump replay — the strictness is upstream's.
