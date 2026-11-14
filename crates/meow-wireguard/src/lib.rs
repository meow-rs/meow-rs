//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! Vendored from <https://github.com/cloudflare/boringtun> v0.7.1 with `ring`
//! replaced by the RustCrypto crates already in the workspace — see
//! `PATCHES.md` for the ordered patch list to replay on a version bump.
//! The upstream `device`, `ffi` and `jni` modules are not vendored.
//!
//! Copyright (c) 2019 Cloudflare, Inc. BSD-3-Clause (see `LICENSE`).

pub mod noise;

#[cfg(feature = "mock-instant")]
pub(crate) mod mock_instant;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

pub(crate) mod crypto;

// PATCH(18): the shared data-plane crypto pool — resident threads that
// open DATA packets through `SessionHandle`s so the receive actors stay
// serial for everything except the AEAD pass itself.
mod crypto_pool;

pub(crate) mod serialization;

pub use crypto_pool::{CryptoJob, CryptoPool};
pub use noise::errors::WireGuardError;
pub use noise::{SessionHandle, Tunn, TunnResult, WireClass, DATA_OVERHEAD_SZ, DATA_PAYLOAD_OFF};

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
