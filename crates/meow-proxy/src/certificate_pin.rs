//! Certificate-pin parsing shared by the SIP003 plugin parsers
//! (gost-plugin, shadow-tls, restls) and the anytls adapter.

use meow_common::error::{MeowError, Result};

/// Parse a `fingerprint` option value: hex (optionally `:`-separated,
/// either case) of the 32-byte SHA-256 of the pinned certificate's DER
/// (upstream `ca.NewFingerprintVerifier`).  uTLS profile names are
/// rejected, mirroring upstream's explicit check.
pub(crate) fn parse_cert_pin(s: &str, context: &str) -> Result<[u8; 32]> {
    // Upstream guards against the easy confusion between this pin and a
    // uTLS ClientHello profile name.
    const UTLS_NAMES: &[&str] = &[
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
    ];
    if UTLS_NAMES.contains(&s.trim().to_ascii_lowercase().as_str()) {
        // No pointer at `client-fingerprint` here: not every caller honours
        // that node-level option (the SIP003 plugins only wire it into
        // shadow-tls's cover handshake) — a hint that is silently ignored
        // elsewhere is worse than none.
        return Err(MeowError::Config(format!(
            "{context}: 'fingerprint' is a TLS certificate pin (SHA-256 hex), \
             not a uTLS ClientHello profile name"
        )));
    }
    let stripped: String = s.trim().replace(':', "");
    let bytes = hex::decode(&stripped)
        .map_err(|e| MeowError::Config(format!("{context}: fingerprint hex decode failed: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        MeowError::Config(format!(
            "{context}: fingerprint must be a SHA-256 hash (32 bytes), got {}",
            bytes.len()
        ))
    })
}
