//! Shared certificate/private-key loading for TLS-terminating listeners.

/// `certificate`/`private-key` → PEM bytes: both `-----BEGIN` strings are
/// inline material; anything else is a pair of file paths resolved through
/// the shared home-contained resolver — the same contract
/// `external-controller-tls` keeps (`load_identity_pair` in meow-api),
/// duplicated here so the listener crate does not depend on the API.
pub(crate) fn load_identity_pair(
    cert: &str,
    key: &str,
    protocol: &str,
) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert_inline = cert.contains("-----BEGIN");
    let key_inline = key.contains("-----BEGIN");
    if cert_inline != key_inline {
        anyhow::bail!(
            "{protocol} certificate and private-key must be both inline PEM or both file paths"
        );
    }
    if cert_inline {
        return Ok((cert.as_bytes().to_vec(), key.as_bytes().to_vec()));
    }
    let cert_path = std::path::Path::new(cert);
    let key_path = std::path::Path::new(key);
    let cert_resolved = meow_config::resolve_home_contained(cert_path)
        .map_err(|e| anyhow::anyhow!("{protocol} certificate: {e}"))?;
    let key_resolved = meow_config::resolve_home_contained(key_path)
        .map_err(|e| anyhow::anyhow!("{protocol} private-key: {e}"))?;
    Ok((
        read_pem_file(&cert_resolved, &format!("{protocol} certificate"))?,
        read_pem_file(&key_resolved, &format!("{protocol} private-key"))?,
    ))
}

/// PEM files are capped like the API endpoint's (`MAX_PEM_FILE_BYTES`
/// there): a certificate chain is tens of KiB, never megabytes.
const MAX_PEM_FILE_BYTES: u64 = 1 << 20;

/// Bounded regular-file PEM read — regular files only, `O_NONBLOCK`
/// against FIFOs, hard byte cap (same discipline as meow-api's
/// `read_pem_file`).
fn read_pem_file(path: &std::path::Path, what: &str) -> Result<Vec<u8>, anyhow::Error> {
    use std::io::Read;
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("{what}: cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("{what}: {} is not a regular file", path.display());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NONBLOCK);
    let file = opts
        .open(path)
        .map_err(|e| anyhow::anyhow!("{what}: cannot open {}: {e}", path.display()))?;
    let mut buf = Vec::new();
    file.take(MAX_PEM_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("{what}: cannot read {}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_PEM_FILE_BYTES {
        anyhow::bail!(
            "{what}: {} exceeds {} bytes",
            path.display(),
            MAX_PEM_FILE_BYTES
        );
    }
    Ok(buf)
}
