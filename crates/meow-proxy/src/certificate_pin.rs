use meow_common::error::{MeowError, Result};

/// Certificate DER SHA-256 pins are distinct from uTLS ClientHello profiles.
pub(crate) fn parse_cert_pin(s: &str, context: &str) -> Result<[u8; 32]> {
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
    if UTLS_NAMES.contains(&s.to_ascii_lowercase().as_str()) {
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
