//! Helpers shared by the in-process SIP003 plugin parsers:
//! `v2ray_plugin`, `gost_plugin`, `shadow_tls_plugin`, `restls_plugin`,
//! `jls_plugin`, `kcptun_plugin`, `ech_tls_tunnel`.

use meow_common::error::{MeowError, Result};
use tracing::warn;

/// SIP003 `plugin-opts` tokenizer shared by every built-in plugin parser:
/// `;`-separated `key=value` tokens, trimmed; a bare key parses as
/// `key=true`.  Keys are lowercased — upstream decodes the opts map
/// through mapstructure, which matches case-insensitively.
pub(crate) fn sip003_opts(s: &str) -> impl Iterator<Item = (String, String)> + '_ {
    s.split(';')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|token| match token.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
            None => (token.to_ascii_lowercase(), "true".to_string()),
        })
}

/// SIP003 boolean convention: `1`/`true`/`yes`/`on` (case-insensitive).
/// Unknown non-empty values warn and coerce to false — the lenient
/// stance `v2ray-plugin`/`ech-tls-tunnel` have always taken; keep it
/// there for compatibility and use [`parse_bool_strict`] for knobs
/// where a typo would silently weaken security (enabling TLS,
/// skipping verification).
pub(crate) fn parse_bool(s: &str, plugin: &str, key: &str) -> bool {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "" | "0" | "false" | "no" | "off" => false,
        other => {
            warn!("{plugin}: unrecognised bool '{other}' for '{key}' — treating as false");
            false
        }
    }
}

/// Strict bool for security-relevant knobs: an unrecognized value is a
/// config error — silently coercing `tls=bogus` to `false` would produce
/// a plaintext transport the operator believes is TLS.
pub(crate) fn parse_bool_strict(s: &str, plugin: &str, key: &str) -> Result<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(MeowError::Config(format!(
            "{plugin}: '{key}' expects a boolean, got '{s}'"
        ))),
    }
}

/// Parse a `fingerprint` option value: `:`-separated hex of the 32-byte
/// SHA-256 of the pinned certificate (upstream
/// `ca.NewFingerprintVerifier`).  uTLS profile names are rejected,
/// mirroring upstream's explicit check.
pub(crate) fn parse_cert_pin(s: &str, plugin: &str) -> Result<[u8; 32]> {
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
    if UTLS_NAMES.contains(&s.to_ascii_lowercase().as_str()) {
        // No pointer at `client-fingerprint` here: that node-level option
        // is only honoured by plugins that wire it into their TLS layer
        // (shadow-tls's cover handshake) — a hint that is silently ignored
        // elsewhere is worse than none.
        return Err(MeowError::Config(format!(
            "{plugin}: 'fingerprint' is a TLS certificate pin (SHA-256 hex), \
             not a uTLS ClientHello profile name"
        )));
    }
    let stripped: String = s.trim().replace(':', "");
    let bytes = hex::decode(&stripped)
        .map_err(|e| MeowError::Config(format!("{plugin}: fingerprint hex decode failed: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        MeowError::Config(format!(
            "{plugin}: fingerprint must be a SHA-256 hash (32 bytes), got {}",
            bytes.len()
        ))
    })
}

/// Upstream `NewTLSKeyPairLoader` accepts PEM content or a file path for
/// `certificate`/`private-key`.  A `-----BEGIN` marker means inline PEM;
/// anything else is read from the filesystem once at config load —
/// callers that want upstream's fswatch-style reload (gost-plugin) use
/// [`pem_source`] to keep the resolved path.
///
/// Note: provider/subscription nodes reach this too (in-process plugins
/// are not gated by `allow-external-plugin`), so a remote feed can point
/// `certificate`/`private-key` at a local path — a file-existence oracle
/// and a way to plant a cert into the TLS config.  That is upstream's
/// semantics verbatim (`NewTLSKeyPairLoader` behaves identically); a
/// deployment accepting untrusted providers should treat these two opts
/// accordingly.  Only the certificate is ever transmitted — private key
/// bytes never leave the host — and the value must still parse as PEM.
/// Relative paths resolve against the meow home dir (upstream `C.Path`),
/// not the process CWD — `resolved_home_dir` carries the `-d` override or
/// the shared XDG config-dir default when no home is set.
pub(crate) fn load_pem_or_path(value: &str, opt: &str, plugin: &str) -> Result<Vec<u8>> {
    match pem_source(value) {
        PemSource::Inline => Ok(value.as_bytes().to_vec()),
        PemSource::File(resolved) => {
            // Never read a non-regular file — a FIFO or device would
            // block the read indefinitely, and a subscription-supplied
            // opt reaches this path (issue #621 review).
            if !resolved.is_file() {
                return Err(MeowError::Config(format!(
                    "{plugin}: '{opt}' is neither inline PEM nor a readable file ({}): \
                     not a regular file",
                    resolved.display()
                )));
            }
            read_cert_file(&resolved).map_err(|e| {
                MeowError::Config(format!(
                    "{plugin}: '{opt}' is neither inline PEM nor a readable file ({}): {e}",
                    resolved.display()
                ))
            })
        }
    }
}

/// Read a cert/key file that an `is_file` check already proved regular.
/// On unix the open carries `O_NONBLOCK` — a path swapped to a FIFO
/// between the stat and this read can't wedge the caller (a nonblocking
/// FIFO read errors instead of blocking; regular files ignore the flag).
pub(crate) fn read_cert_file(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let mut f = opts.open(path)?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut buf)?;
    Ok(buf)
}

/// Where a `certificate`/`private-key` opt value's PEM bytes live —
/// classified by the same `-----BEGIN` rule [`load_pem_or_path`] uses.
/// Consumers that support hot reload (gost-plugin; upstream
/// `NewTLSKeyPairLoader` + fswatch) keep the [`PemSource::File`] path so
/// they can re-stat and re-read it per dial.
pub(crate) enum PemSource {
    /// PEM content inline in the opt value — immutable.
    Inline,
    /// Filesystem path, already resolved against the meow home dir.
    File(std::path::PathBuf),
}

impl PemSource {
    /// The resolved path when the value named a file, else `None`.
    pub(crate) fn into_path(self) -> Option<std::path::PathBuf> {
        match self {
            PemSource::File(p) => Some(p),
            PemSource::Inline => None,
        }
    }
}

/// Classify a PEM opt value without reading it (see [`PemSource`]).
pub(crate) fn pem_source(value: &str) -> PemSource {
    if value.contains("-----BEGIN") {
        PemSource::Inline
    } else {
        let path = std::path::Path::new(value);
        PemSource::File(if path.is_absolute() {
            path.to_path_buf()
        } else {
            meow_common::resolved_home_dir().join(path)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip003_opts_tokenizes_and_lowercases_keys() {
        let got: Vec<_> = sip003_opts(" Host=example.com ;TLS; path = /x ;").collect();
        assert_eq!(
            got,
            [
                ("host".to_string(), "example.com".to_string()),
                ("tls".to_string(), "true".to_string()),
                ("path".to_string(), "/x".to_string()),
            ]
        );
        // A value may itself contain `=` (base64, query strings).
        assert_eq!(
            sip003_opts("k=a=b=c").collect::<Vec<_>>(),
            [("k".to_string(), "a=b=c".to_string())]
        );
        assert_eq!(sip003_opts("  ;; ").next(), None);
    }

    #[test]
    fn parse_bool_lenient_vs_strict() {
        assert!(parse_bool("YES", "p", "k"));
        assert!(!parse_bool("bogus", "p", "k"));
        assert!(parse_bool_strict("on", "p", "k").unwrap());
        assert!(parse_bool_strict("bogus", "p", "k").is_err());
        // Strict also rejects the lenient empty-string coercion.
        assert!(parse_bool_strict("", "p", "k").is_err());
    }

    #[test]
    fn cert_pin_rejects_utls_names_and_bad_hex() {
        assert!(parse_cert_pin("chrome", "p").is_err());
        assert!(parse_cert_pin("zz".repeat(32).as_str(), "p").is_err());
        assert!(parse_cert_pin(&"ab".repeat(31), "p").is_err()); // 31 bytes
        assert!(
            parse_cert_pin(&"ab".repeat(32), "p").is_ok(),
            "64 hex chars without colons"
        );
        assert!(parse_cert_pin(&"ab:".repeat(32)[..95], "p").is_ok());
    }
}
