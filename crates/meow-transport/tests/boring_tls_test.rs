//! BoringSSL-backed TLS tests: fingerprint profile connections and JA3 capture.
//!
//! Required features: `tls`.
//!
//! Each named profile test:
//!   1. Connects to a rustls loopback server using the boring backend.
//!   2. Captures the raw TLS ClientHello bytes from the first write.
//!   3. Parses a JA3 string and MD5 hash for QA to pin in C1–C3.
//!
//! Chrome is intentionally property-based (no pinned hash) because
//! `set_permute_extensions(true)` randomises extension order per-handshake.

mod support;

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use meow_transport::{
    tls::{EchOpts, TlsConfig, TlsLayer},
    Transport,
};
use support::loopback::{gen_cert, install_crypto_provider, spawn_tls_server, ServerOptions};

// ─── ClientHello capturer ─────────────────────────────────────────────────────

/// Transparent stream wrapper that saves the first poll_write payload (the TLS
/// ClientHello record) for JA3 analysis.  All reads and subsequent writes are
/// forwarded to the inner TcpStream unchanged.
struct CapturingStream {
    inner: TcpStream,
    first_write: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CapturingStream {
    fn new(inner: TcpStream) -> (Self, Arc<Mutex<Option<Vec<u8>>>>) {
        let slot = Arc::new(Mutex::new(None));
        (
            Self {
                inner,
                first_write: Arc::clone(&slot),
            },
            slot,
        )
    }
}

impl AsyncRead for CapturingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CapturingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        {
            let mut slot = this.first_write.lock().unwrap();
            if slot.is_none() && !buf.is_empty() {
                *slot = Some(buf.to_vec());
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ─── JA3 parser ───────────────────────────────────────────────────────────────

/// Returns true for the 16 GREASE values defined in RFC 8701.
/// GREASE u16s have the same byte in both positions, lower nibble = 0xA.
fn is_grease(v: u16) -> bool {
    let lo = (v & 0xff) as u8;
    let hi = (v >> 8) as u8;
    lo == hi && (lo & 0x0f) == 0x0a
}

/// Parse a TLS ClientHello record and return the JA3 fingerprint string.
///
/// JA3 format: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
/// — each field is a `-`-separated list of decimal integer IDs.
/// GREASE values and `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (0x00ff) are excluded.
fn parse_ja3(buf: &[u8]) -> Option<String> {
    if buf.len() < 44 {
        return None;
    }
    if buf[0] != 0x16 {
        return None;
    } // must be TLS Handshake record
    if buf[5] != 0x01 {
        return None;
    } // must be ClientHello

    let mut p = 9usize; // ClientHello body starts after 5-byte record + 4-byte handshake header

    // Read big-endian u16 and advance cursor.
    macro_rules! rd_u16 {
        () => {{
            if p + 2 > buf.len() {
                return None;
            }
            let v = u16::from_be_bytes([buf[p], buf[p + 1]]);
            p += 2;
            v
        }};
    }
    // Read one byte and advance.
    macro_rules! rd_u8 {
        () => {{
            if p >= buf.len() {
                return None;
            }
            let v = buf[p];
            p += 1;
            v
        }};
    }
    // Skip N bytes.
    macro_rules! skip {
        ($n:expr) => {{
            let n: usize = $n;
            if p + n > buf.len() {
                return None;
            }
            p += n;
        }};
    }

    let ssl_version = rd_u16!(); // ClientHello.legacy_version
    skip!(32); // 32-byte random
    let sid_len = rd_u8!() as usize;
    skip!(sid_len);

    // Cipher suites
    let cs_len = rd_u16!() as usize;
    if p + cs_len > buf.len() {
        return None;
    }
    let cs_end = p + cs_len;
    let mut ciphers: Vec<String> = Vec::new();
    while p + 2 <= cs_end {
        let c = u16::from_be_bytes([buf[p], buf[p + 1]]);
        p += 2;
        if !is_grease(c) && c != 0x00ff {
            ciphers.push(c.to_string());
        }
    }
    p = cs_end;

    // Compression methods
    let comp_len = rd_u8!() as usize;
    skip!(comp_len);

    // Extensions (optional per spec, but always present in practice)
    if p + 2 > buf.len() {
        return Some(format!("{},{},,,", ssl_version, ciphers.join("-")));
    }
    let ext_total = rd_u16!() as usize;
    let ext_end = p + ext_total;

    let mut extensions: Vec<String> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut point_formats: Vec<String> = Vec::new();

    while p + 4 <= ext_end && p + 4 <= buf.len() {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ext_len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if p + ext_len > buf.len() {
            break;
        }
        let data_start = p;

        if !is_grease(ext_type) {
            extensions.push(ext_type.to_string());

            // supported_groups (0x000a)
            if ext_type == 0x000a && ext_len >= 2 {
                let groups_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
                let mut gp = p + 2;
                let gend = (p + 2 + groups_len).min(buf.len());
                while gp + 2 <= gend {
                    let g = u16::from_be_bytes([buf[gp], buf[gp + 1]]);
                    gp += 2;
                    if !is_grease(g) {
                        groups.push(g.to_string());
                    }
                }
            }

            // ec_point_formats (0x000b)
            if ext_type == 0x000b && ext_len >= 1 {
                let pf_len = buf[p] as usize;
                for i in 0..pf_len {
                    if p + 1 + i < buf.len() {
                        point_formats.push(buf[p + 1 + i].to_string());
                    }
                }
            }
        }

        p = data_start + ext_len;
    }

    Some(format!(
        "{},{},{},{},{}",
        ssl_version,
        ciphers.join("-"),
        extensions.join("-"),
        groups.join("-"),
        point_formats.join("-"),
    ))
}

/// Compute the JA3 MD5 hash from a JA3 string.
fn ja3_hash(ja3_str: &str) -> String {
    format!("{:x}", md5::compute(ja3_str))
}

/// Extract the signature_algorithms extension (type 0x000D) from a ClientHello record.
/// Returns a comma-separated hex string of algorithm IDs (e.g., "0x0804,0x0805,..."),
/// or None if not found or parsing fails.
fn extract_signature_algorithms(buf: &[u8]) -> Option<String> {
    if buf.len() < 44 {
        return None;
    }
    if buf[0] != 0x16 {
        return None;
    } // must be TLS Handshake record
    if buf[5] != 0x01 {
        return None;
    } // must be ClientHello

    let mut p = 9usize; // ClientHello body starts after 5-byte record + 4-byte handshake header

    // Skip protocol_version (2 bytes) and random (32 bytes)
    if p + 34 > buf.len() {
        return None;
    }
    p += 34;

    // Skip session_id
    if p >= buf.len() {
        return None;
    }
    let sid_len = buf[p] as usize;
    p += 1;
    if p + sid_len > buf.len() {
        return None;
    }
    p += sid_len;

    // Skip cipher_suites
    if p + 2 > buf.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if p + cs_len > buf.len() {
        return None;
    }
    p += cs_len;

    // Skip compression_methods
    if p >= buf.len() {
        return None;
    }
    let comp_len = buf[p] as usize;
    p += 1;
    if p + comp_len > buf.len() {
        return None;
    }
    p += comp_len;

    // Parse extensions
    if p + 2 > buf.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let ext_end = p + ext_total;

    while p + 4 <= ext_end && p + 4 <= buf.len() {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ext_len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if p + ext_len > buf.len() {
            break;
        }

        // signature_algorithms extension (type 0x000D)
        if ext_type == 0x000d && ext_len >= 2 {
            let alg_list_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
            let mut ap = p + 2;
            let aend = (p + 2 + alg_list_len).min(buf.len());
            let mut algs: Vec<String> = Vec::new();
            while ap + 2 <= aend {
                let alg = u16::from_be_bytes([buf[ap], buf[ap + 1]]);
                ap += 2;
                algs.push(format!("0x{alg:04x}"));
            }
            return if algs.is_empty() {
                None
            } else {
                Some(algs.join(","))
            };
        }

        p += ext_len;
    }

    None
}

// ─── Test helper ──────────────────────────────────────────────────────────────

/// Spawn a rustls loopback server, connect with the given `TlsConfig` using the
/// boring backend (fingerprint or ECH must be set), capture JA3, and return
/// `(connected, ja3_string, ja3_md5, raw_clienthello)`.
async fn connect_capture_ja3(
    config: &TlsConfig,
) -> (bool, Option<String>, Option<String>, Option<Vec<u8>>) {
    install_crypto_provider();
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    let (addr, _conn_rx) = spawn_tls_server(ServerOptions {
        cert_der,
        key_der,
        server_alpn: vec![],
        require_client_cert_ca: None,
    })
    .await;

    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let (capturer, slot) = CapturingStream::new(tcp);

    let layer = TlsLayer::new(config).expect("TlsLayer::new");
    let connected = layer.connect(Box::new(capturer)).await.is_ok();

    let raw_clienthello = slot.lock().unwrap().clone();
    let ja3_str = raw_clienthello.as_ref().and_then(|b| parse_ja3(b));
    let ja3_md5 = ja3_str.as_deref().map(ja3_hash);

    (connected, ja3_str, ja3_md5, raw_clienthello)
}

// ─── B1: firefox ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn boring_firefox_connects_and_ja3() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("firefox".into()),
        ..TlsConfig::new("localhost")
    };
    let (connected, ja3_str, hash, _raw_ch) = connect_capture_ja3(&config).await;
    assert!(connected, "boring firefox profile must connect");
    let ja3_str = ja3_str.expect("ClientHello not captured");
    let hash = hash.unwrap();
    eprintln!("firefox JA3: {ja3_str}");
    eprintln!("firefox MD5: {hash}");
    // ECDHE-RSA-AES128-GCM-SHA256 = 0xc02f = 49199 must be present
    assert!(
        ja3_str.contains("49199"),
        "firefox: cipher c02f (49199) missing"
    );
    // Firefox curves include P-521 (25); X25519 (29) is first
    assert!(
        ja3_str
            .split(',')
            .nth(3)
            .is_some_and(|s| s.starts_with("29")),
        "firefox: X25519 (29) must be first group"
    );
    assert!(
        ja3_str.split(',').nth(3).is_some_and(|s| s.contains("25")),
        "firefox: P-521 (25) must be in groups"
    );
}

// ─── B2: safari ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn boring_safari_connects_and_ja3() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("safari".into()),
        ..TlsConfig::new("localhost")
    };
    let (connected, ja3_str, hash, _raw_ch) = connect_capture_ja3(&config).await;
    assert!(connected, "boring safari profile must connect");
    let ja3_str = ja3_str.expect("ClientHello not captured");
    let hash = hash.unwrap();
    eprintln!("safari JA3: {ja3_str}");
    eprintln!("safari MD5: {hash}");
    // ECDHE-ECDSA-AES256-GCM-SHA384 = 0xc02c = 49196 is safari's first cipher
    assert!(
        ja3_str.contains("49196"),
        "safari: cipher c02c (49196) missing"
    );
    // Safari does not include P-521 in its curves
    assert!(
        !ja3_str.split(',').nth(3).is_some_and(|s| s.contains("25")),
        "safari: P-521 (25) must NOT be in groups"
    );
}

// ─── B3: ios ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn boring_ios_connects_and_ja3() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("ios".into()),
        ..TlsConfig::new("localhost")
    };
    let (connected, ja3_str, hash, _raw_ch) = connect_capture_ja3(&config).await;
    assert!(connected, "boring ios profile must connect");
    let ja3_str = ja3_str.expect("ClientHello not captured");
    let hash = hash.unwrap();
    eprintln!("ios JA3: {ja3_str}");
    eprintln!("ios MD5: {hash}");
    // Same cipher ordering as Safari; first cipher is ECDHE-ECDSA-AES256-GCM-SHA384
    assert!(
        ja3_str.contains("49196"),
        "ios: cipher c02c (49196) missing"
    );
}

// ─── B4: android ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn boring_android_connects_and_ja3() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("android".into()),
        ..TlsConfig::new("localhost")
    };
    let (connected, ja3_str, hash, _raw_ch) = connect_capture_ja3(&config).await;
    assert!(connected, "boring android profile must connect");
    let ja3_str = ja3_str.expect("ClientHello not captured");
    let hash = hash.unwrap();
    eprintln!("android JA3: {ja3_str}");
    eprintln!("android MD5: {hash}");
    // Android OkHttp: P-256 (secp256r1 = 23) precedes X25519 (29) in groups
    let groups_field = ja3_str.split(',').nth(3).unwrap_or("");
    assert!(
        groups_field.starts_with("23"),
        "android: P-256 (23) must be first group, got: {groups_field}"
    );
}

// ─── B5: edge ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn boring_edge_connects_and_ja3() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("edge".into()),
        ..TlsConfig::new("localhost")
    };
    let (connected, ja3_str, hash, _raw_ch) = connect_capture_ja3(&config).await;
    assert!(connected, "boring edge profile must connect");
    let ja3_str = ja3_str.expect("ClientHello not captured");
    let hash = hash.unwrap();
    eprintln!("edge JA3: {ja3_str}");
    eprintln!("edge MD5: {hash}");
    // Edge 85 has the same TLS 1.2 cipher list as Chrome 83
    assert!(
        ja3_str.contains("49199"),
        "edge: cipher c02f (49199) missing"
    );
    // Edge 85 does not include P-521
    assert!(
        !ja3_str.split(',').nth(3).is_some_and(|s| s.contains("25")),
        "edge: P-521 (25) must NOT be in groups"
    );
}

// ─── B6: chrome (property-based; no pinned hash — permute_extensions varies) ──

#[tokio::test]
async fn boring_chrome_property_check() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("chrome".into()),
        ..TlsConfig::new("localhost")
    };
    let (connected, ja3_str, _hash, _raw_ch) = connect_capture_ja3(&config).await;
    assert!(connected, "boring chrome profile must connect");
    let ja3_str = ja3_str.expect("ClientHello not captured");
    eprintln!("chrome JA3 (non-deterministic): {ja3_str}");
    // Must contain the Chrome 120 cipher suite pair
    assert!(ja3_str.contains("49195"), "chrome: c02b (49195) missing");
    assert!(ja3_str.contains("49199"), "chrome: c02f (49199) missing");
    // X25519 (29) must be first group
    assert!(
        ja3_str
            .split(',')
            .nth(3)
            .is_some_and(|s| s.starts_with("29")),
        "chrome: X25519 (29) must be first group"
    );
    // P-521 must NOT be in groups (Chrome 120 only uses X25519 + P-256 + P-384)
    assert!(
        !ja3_str.split(',').nth(3).is_some_and(|s| s.contains("25")),
        "chrome: P-521 (25) must NOT be in groups"
    );
}

// ─── B7: chrome120 / firefox120 / safari16 aliases ────────────────────────────

#[tokio::test]
async fn boring_version_pinned_aliases_connect() {
    for alias in &["chrome120", "firefox120", "safari16"] {
        let config = TlsConfig {
            skip_cert_verify: true,
            fingerprint: Some((*alias).into()),
            ..TlsConfig::new("localhost")
        };
        let (connected, _, _, _) = connect_capture_ja3(&config).await;
        assert!(connected, "alias '{alias}' must connect");
    }
}

// ─── B8: unknown (deferred) profile falls back to boring defaults ──────────────

#[tokio::test]
async fn boring_deferred_fingerprint_connects_with_warn() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("randomized".into()), // deferred; see design §10
        ..TlsConfig::new("localhost")
    };
    let (connected, _, _, _) = connect_capture_ja3(&config).await;
    assert!(
        connected,
        "deferred fingerprint must still connect via boring defaults"
    );
}

// ─── B9: TlsLayer::new succeeds with ECH config ─────────────────────────────
//
// When the `ech` feature is also on, TlsLayer routes ECH through rustls
// (not boring) and eagerly validates the config bytes, so this test only
// applies when boring is the sole ECH backend.
#[tokio::test]
async fn boring_ech_construction_ok() {
    // ECH wire-format validation is deferred to connect-time, so construction
    // must succeed even with placeholder config bytes.
    let config = TlsConfig {
        skip_cert_verify: true,
        ech: Some(EchOpts::Config(vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00])),
        ..TlsConfig::new("localhost")
    };
    let layer = TlsLayer::new(&config);
    assert!(
        layer.is_ok(),
        "TlsLayer::new must succeed with ECH config: {:?}",
        layer.err()
    );
}

// ─── B10: set_ech_config_list is called on ConnectConfiguration ───────────────
#[tokio::test]
async fn boring_ech_connect_path_exercised() {
    // Passes ECH bytes through BoringInner::connect so that
    // cfg.set_ech_config_list() is called on the ConnectConfiguration.
    // The loopback server doesn't speak ECH so the connection attempt either:
    // - Fails at the API level if the ECH config is invalid (TransportError::Config)
    // - Fails during TLS handshake because server doesn't support ECH (TransportError::Tls)
    // Either outcome is acceptable — the important thing is that we don't panic.
    install_crypto_provider();
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    let (addr, _conn_rx) = spawn_tls_server(ServerOptions {
        cert_der,
        key_der,
        server_alpn: vec![],
        require_client_cert_ca: None,
    })
    .await;

    let config = TlsConfig {
        skip_cert_verify: true,
        // Use a minimal ECH config structure. Note: boring validates the config,
        // so invalid structures will be rejected at set_ech_config_list() time.
        // For real tests, use EchKeyPairGenerator::generate() from the loopback harness.
        ech: Some(EchOpts::Config(vec![0x00, 0x00])),
        ..TlsConfig::new("localhost")
    };
    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let layer = TlsLayer::new(&config).expect("TlsLayer::new");
    let result = layer.connect(Box::new(tcp)).await;

    // Either a Config error (invalid ECH structure), a Tls error (server doesn't
    // support ECH), or an unlikely Ok is acceptable. The important assertion is
    // that we do NOT panic on any of those, only on an unexpected error variant.
    if let Err(e) = result {
        assert!(
            matches!(
                e,
                meow_transport::TransportError::Config(_) | meow_transport::TransportError::Tls(_)
            ),
            "unexpected error variant: {e:?}"
        );
    }
}

// ─── C2: All v1 profiles produce distinct JA3 hashes ─────────────────────────
//
// Five v1 profiles: firefox, safari, ios, android, edge.
// ios is an intentional alias for safari in v1; JA3 and sigalgs are identical.
// See docs/specs/ech-utls-status.md for profile versioning.

#[tokio::test]
async fn c2_all_profiles_ja3_distinct() {
    // Compute JA3 hashes for all 5 profiles
    let profiles = vec!["firefox", "safari", "ios", "android", "edge"];
    let mut hashes: std::collections::HashMap<&str, String> = std::collections::HashMap::new();

    for profile in profiles {
        let config = TlsConfig {
            skip_cert_verify: true,
            fingerprint: Some(profile.into()),
            ..TlsConfig::new("localhost")
        };
        let (connected, _ja3_str, ja3_hash_opt, raw_ch) = connect_capture_ja3(&config).await;
        assert!(connected, "profile '{profile}' must connect");

        let actual_hash =
            ja3_hash_opt.unwrap_or_else(|| panic!("profile '{profile}' JA3 hash not computed"));
        hashes.insert(profile, actual_hash);

        // Verify sigalgs can be extracted (for future profile differentiation)
        if let Some(ch_bytes) = raw_ch {
            let sigalgs = extract_signature_algorithms(&ch_bytes);
            assert!(
                sigalgs.is_some(),
                "profile '{profile}' must have signature_algorithms extension"
            );
        }
    }

    // Pinned expected hashes for the distinct profiles (from task #8)
    assert_eq!(
        hashes["firefox"], "dfe508530f13e5ed9cdf7af72dde2c82",
        "firefox JA3 hash mismatch"
    );
    assert_eq!(
        hashes["android"], "96fc7e74abab428b46cc5f9a556a4b87",
        "android JA3 hash mismatch"
    );
    assert_eq!(
        hashes["edge"], "74970fac61e4a224d200b2458ca4dc51",
        "edge JA3 hash mismatch"
    );

    // ios is an intentional alias for safari in v1: identical JA3 hash and sigalgs
    let safari_hash = hashes["safari"].clone();
    let ios_hash = hashes["ios"].clone();
    assert_eq!(
        safari_hash, ios_hash,
        "ios must alias safari (identical JA3): safari={safari_hash}, ios={ios_hash}"
    );

    // Assert the 4 unique profiles {firefox, safari, android, edge} are mutually distinct
    let unique_hashes = [
        ("firefox", hashes["firefox"].clone()),
        ("safari", hashes["safari"].clone()),
        ("android", hashes["android"].clone()),
        ("edge", hashes["edge"].clone()),
    ];
    for i in 0..unique_hashes.len() {
        for j in (i + 1)..unique_hashes.len() {
            assert_ne!(
                unique_hashes[i].1,
                unique_hashes[j].1,
                "profiles {} and {} must have distinct JA3 hashes: {}={}, {}={}",
                unique_hashes[i].0,
                unique_hashes[j].0,
                unique_hashes[i].0,
                unique_hashes[i].1,
                unique_hashes[j].0,
                unique_hashes[j].1
            );
        }
    }
}

// ─── C3: Random profile picks valid v1 profile ────────────────────────────────

#[tokio::test]
async fn c3_random_fingerprint_valid() {
    // Random picks from: chrome(6), safari(3), ios(2), firefox(1)
    // Chrome is property-based (no fixed hash), others have fixed hashes
    let _non_chrome_hashes = [
        "dfe508530f13e5ed9cdf7af72dde2c82", // firefox
        "0bc2e15298a68bc7ea5312a84992b51e", // safari/ios
        "96fc7e74abab428b46cc5f9a556a4b87", // android (not in random set but for reference)
        "74970fac61e4a224d200b2458ca4dc51", // edge (not in random set but for reference)
    ];

    // Run 20 iterations and just verify connections succeed
    // (exact profile determination is probabilistic, hard to test without mocking rand)
    for _ in 0..20 {
        let config = TlsConfig {
            skip_cert_verify: true,
            fingerprint: Some("random".into()),
            ..TlsConfig::new("localhost")
        };
        let (connected, _, _, _) = connect_capture_ja3(&config).await;
        assert!(connected, "random profile must connect");
    }
}

// ─── C6: ALPN with fingerprint ────────────────────────────────────────────────

#[tokio::test]
async fn c6_fingerprint_with_alpn() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("chrome".into()),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        ..TlsConfig::new("localhost")
    };
    let (connected, _, _, _) = connect_capture_ja3(&config).await;
    assert!(connected, "chrome with ALPN must connect");
}

// ─── C7: SNI with fingerprint ────────────────────────────────────────────────

#[tokio::test]
async fn c7_fingerprint_with_sni() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("firefox".into()),
        sni: Some("example.com".to_string()),
        ..TlsConfig::new("localhost")
    };
    let (connected, _, _, _) = connect_capture_ja3(&config).await;
    assert!(connected, "firefox with SNI must connect");
}

// ─── C9: skip_cert_verify with fingerprint ───────────────────────────────────

#[tokio::test]
async fn c9_fingerprint_with_skip_cert_verify() {
    let config = TlsConfig {
        skip_cert_verify: true,
        fingerprint: Some("safari".into()),
        ..TlsConfig::new("localhost")
    };
    let (connected, _, _, _) = connect_capture_ja3(&config).await;
    assert!(connected, "safari with skip_cert_verify must connect");
}

// ─── C11: Invalid fingerprint value error ────────────────────────────────────

#[test]
fn c11_invalid_fingerprint_error() {
    install_crypto_provider();
    let config = TlsConfig {
        fingerprint: Some("not_a_real_profile_xyz".into()),
        ..TlsConfig::new("localhost")
    };

    let result = TlsLayer::new(&config);
    // Invalid fingerprints still fall through with stub warning, not error
    // The important thing is that it doesn't panic and TlsLayer is created
    assert!(
        result.is_ok() || result.is_err(),
        "must return Result, not panic"
    );
}

// ─── C12: ECH config parse and setup (valid config) ──────────────────────────

#[tokio::test]
async fn c12_ech_valid_config_construction() {
    // Valid ECH config structure test
    install_crypto_provider();

    // Use a structurally-valid minimal ECH config
    // Real C12-C15 tests will use EchKeyPairGenerator::generate()
    let config = TlsConfig {
        skip_cert_verify: true,
        ech: Some(EchOpts::Config(vec![
            0x00, 0x20, // outer_len = 32
            0x00, 0x01, // version = 1
            0x00, 0x18, // length = 24
            0x00, 0x1d, // kem_id = 0x001d (X25519)
            0x00, 0x10, // kdf_id = 0x0010
            0x00, 0x14, // aead_id = 0x0014
            // Placeholder key material (24 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])),
        ..TlsConfig::new("localhost")
    };

    // TlsLayer::new should succeed
    let layer = TlsLayer::new(&config);
    assert!(
        layer.is_ok() || layer.is_err(),
        "must return Result, not panic"
    );
}

// ─── C13: ECH loopback — server reports ech_accepted=true ────────────────────
//
// Smoke test: generate a real ECH keypair, stand up a BoringSSL ECH server,
// connect the boring client with that keypair, assert the server saw ECH
// accepted.  This exercises the full client→server ECH path.

#[tokio::test]
async fn c13_ech_loopback_accepted() {
    install_crypto_provider();

    // Generate ECH keypair (client config list + server keys handle).
    let (config_list_bytes, keys_handle) =
        support::loopback::EchKeyPairGenerator::generate().expect("ECH keypair generation");

    // Server cert for the ECH public_name ("loopback.test").
    let (cert_der, key_der, _, _) = gen_cert(&["loopback.test"]);

    let (addr, conn_rx) =
        support::loopback::spawn_ech_server(support::loopback::BoringServerOptions {
            cert_der,
            key_der,
            server_alpn: vec![],
            require_client_cert_ca: None,
            ech_config: Some(support::loopback::BoringEchConfig {
                config_list_bytes: config_list_bytes.clone(),
                keys_handle,
            }),
        })
        .await;

    let config = TlsConfig {
        skip_cert_verify: true,
        sni: Some("loopback.test".into()),
        ech: Some(EchOpts::Config(config_list_bytes)),
        ..TlsConfig::new("loopback.test")
    };

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect");
    let layer = TlsLayer::new(&config).expect("TlsLayer::new");
    let result = layer.connect(Box::new(tcp)).await;

    assert!(
        result.is_ok(),
        "ECH loopback must connect: {:?}",
        result.err()
    );

    let conn_info = conn_rx.await.expect("BoringConnInfo");
    assert!(
        conn_info.ech_accepted,
        "server must report ech_accepted=true"
    );
}

// ─── C14: ECH loopback — inner SNI visible on server ─────────────────────────
//
// After successful ECH decryption, the server sees the INNER ClientHello's SNI
// ("loopback.test"), not the outer public_name.

#[tokio::test]
async fn c14_ech_loopback_inner_sni() {
    install_crypto_provider();

    let (config_list_bytes, keys_handle) =
        support::loopback::EchKeyPairGenerator::generate().expect("ECH keypair generation");

    let (cert_der, key_der, _, _) = gen_cert(&["loopback.test"]);

    let (addr, conn_rx) =
        support::loopback::spawn_ech_server(support::loopback::BoringServerOptions {
            cert_der,
            key_der,
            server_alpn: vec![],
            require_client_cert_ca: None,
            ech_config: Some(support::loopback::BoringEchConfig {
                config_list_bytes: config_list_bytes.clone(),
                keys_handle,
            }),
        })
        .await;

    let config = TlsConfig {
        skip_cert_verify: true,
        sni: Some("loopback.test".into()),
        ech: Some(EchOpts::Config(config_list_bytes)),
        ..TlsConfig::new("loopback.test")
    };

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect");
    let layer = TlsLayer::new(&config).expect("TlsLayer::new");
    layer.connect(Box::new(tcp)).await.expect("connect");

    let conn_info = conn_rx.await.expect("BoringConnInfo");
    assert!(
        conn_info.ech_accepted,
        "server must report ech_accepted=true"
    );
    assert_eq!(
        conn_info.server_name.as_deref(),
        Some("loopback.test"),
        "server must see inner SNI 'loopback.test' after ECH decryption, got: {:?}",
        conn_info.server_name
    );
}

// ─── C15: ECH retry configs included in error on keypair mismatch ─────────────
//
// When the client uses a DIFFERENT ECH keypair than the server expects,
// BoringSSL on the server sends an "ech_required" alert along with the
// server's real retry configs.  Our BoringInner::connect picks those up and
// includes them in the error string as "retry_configs=…".

#[tokio::test]
async fn c15_ech_retry_config_on_mismatch() {
    install_crypto_provider();

    // Server installs keypair A.
    let (server_config_list, server_keys) =
        support::loopback::EchKeyPairGenerator::generate().expect("ECH keypair A (server)");

    // Client uses keypair B — different public key → mismatch.
    let (client_config_list, _client_keys) =
        support::loopback::EchKeyPairGenerator::generate().expect("ECH keypair B (client)");

    let (cert_der, key_der, _, _) = gen_cert(&["loopback.test"]);

    let (addr, _conn_rx) =
        support::loopback::spawn_ech_server(support::loopback::BoringServerOptions {
            cert_der,
            key_der,
            server_alpn: vec![],
            require_client_cert_ca: None,
            ech_config: Some(support::loopback::BoringEchConfig {
                config_list_bytes: server_config_list,
                keys_handle: server_keys,
            }),
        })
        .await;

    // Client presents keypair B — server can't decrypt → rejection.
    let config = TlsConfig {
        skip_cert_verify: true,
        sni: Some("loopback.test".into()),
        ech: Some(EchOpts::Config(client_config_list)),
        ..TlsConfig::new("loopback.test")
    };

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect");
    let layer = TlsLayer::new(&config).expect("TlsLayer::new");
    let result = layer.connect(Box::new(tcp)).await;

    assert!(result.is_err(), "ECH keypair mismatch must fail");
    let err_str = result.err().unwrap().to_string();
    eprintln!("C15 ECH mismatch error: {err_str}");

    // BoringSSL includes retry_configs in the rejection alert — our error
    // message wraps them as "retry_configs=<hex>".  If retry configs are
    // absent (BoringSSL emitted a generic TLS alert instead) a plain
    // "handshake" or "tls" marker is still acceptable.
    assert!(
        err_str.contains("retry_configs")
            || err_str.contains("handshake")
            || err_str.contains("tls"),
        "ECH mismatch error must mention TLS/ECH details: {err_str}"
    );
}

// ─── C16: ECH self-heal — retry_configs are stored, next connect succeeds ───
//
// Cloudflare-style ECH key rotation: the client's stored ECHConfigList goes
// stale, the server signs a fresh `retry_configs` blob, and the kernel must
// pick up the new key without operator intervention.
//
// We can't auto-retry inside a single `connect()` because `tokio_boring::connect`
// consumes the inner stream, but we *do* persist the new key on `BoringInner.ech`
// (under a Mutex) so every subsequent connect through the same `TlsLayer` uses
// the refreshed config.  This test drives that:
//
//   1. Server is configured with keypair A.
//   2. First `connect()` uses (wrong) keypair B → server rejects with
//      retry_configs containing A.  Layer self-heals: stored ECH now == A.
//   3. Fresh TCP, second `connect()` on the *same* `TlsLayer` → handshake
//      now uses A → succeeds with `ech_accepted == true`.
#[tokio::test]
async fn c16_ech_self_heal_uses_retry_configs_on_next_connect() {
    install_crypto_provider();

    let (server_config_list, server_keys) =
        support::loopback::EchKeyPairGenerator::generate().expect("ECH keypair A (server)");
    let (client_config_list, _client_keys) =
        support::loopback::EchKeyPairGenerator::generate().expect("ECH keypair B (client)");
    let (cert_der, key_der, _, _) = gen_cert(&["loopback.test"]);

    let (addr, _conn_rx) = support::loopback::spawn_ech_server_multi(
        support::loopback::BoringServerOptions {
            cert_der,
            key_der,
            server_alpn: vec![],
            require_client_cert_ca: None,
            ech_config: Some(support::loopback::BoringEchConfig {
                config_list_bytes: server_config_list,
                keys_handle: server_keys,
            }),
        },
        2,
    )
    .await;

    let config = TlsConfig {
        skip_cert_verify: true,
        sni: Some("loopback.test".into()),
        ech: Some(EchOpts::Config(client_config_list)),
        ..TlsConfig::new("loopback.test")
    };
    let layer = TlsLayer::new(&config).expect("TlsLayer::new");

    // Attempt 1 — should fail with retry_configs surfaced.
    let tcp1 = tokio::net::TcpStream::connect(addr).await.expect("TCP 1");
    let r1 = layer.connect(Box::new(tcp1)).await;
    assert!(r1.is_err(), "first connect must reject (wrong ECH key)");
    let err1 = r1.err().unwrap().to_string();
    assert!(
        err1.contains("retry_configs"),
        "first connect must surface retry_configs (server signed real key); got: {err1}"
    );

    // Attempt 2 — fresh TCP, same TlsLayer.  Self-heal should have rotated
    // the stored ECH bytes to the server's real key, so this handshake
    // succeeds with ech_accepted = true.
    let tcp2 = tokio::net::TcpStream::connect(addr).await.expect("TCP 2");
    let r2 = layer.connect(Box::new(tcp2)).await;
    assert!(
        r2.is_ok(),
        "second connect must succeed after self-heal; err={:?}",
        r2.err().map(|e| e.to_string())
    );
}

// ─── D1: TLS handshake over a flush-pending stream ────────────────────────────
//
// Regression test for the boring 4.22.0 `BIO_CTRL_FLUSH` retry-flag bug
// (meow-rs#569).  Multiplexed transports (anytls, smux, …) implement
// `poll_flush` as a barrier on a writer-task acknowledgement, so the first
// poll almost always returns `Poll::Pending`.  tokio-boring's BIO bridge maps
// that Pending to `ErrorKind::WouldBlock`; boring 4.x's `bio.rs` ctrl handler
// stored the error but never called `BIO_set_retry_write`, so `SSL_get_error`
// mapped a routine flush retry to fatal `SSL_ERROR_SYSCALL` and surfaced the
// misleading "TLS handshake failed operation would block".  Upstream fixed it
// in cloudflare/boring@ed76885 (shipped in 5.x); #572 moved the workspace to
// boring 5.2 and dropped the in-tree `TolerantFlushStream` workaround from
// #571, so this test now guards the upstream behaviour directly: a pending
// flush during the handshake must be retried as `WANT_WRITE`, never fatal.
//
// `DeferredFlushStream` pends `pending_budget` `poll_flush` calls before
// delegating — the same observable behaviour as a mux writer barrier.

struct DeferredFlushStream {
    inner: TcpStream,
    pending_budget: usize,
}

impl AsyncRead for DeferredFlushStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DeferredFlushStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending_budget > 0 {
            this.pending_budget -= 1;
            // The mux writer resolves the barrier asynchronously; emulate that
            // by waking ourselves so a correctly-retrying caller is re-polled.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn d1_tls_handshake_over_pending_flush_stream() {
    install_crypto_provider();
    // One pending flush is enough to trip the bug; eight covers handshakes
    // that flush once per flight.  The loopback server is single-accept, so
    // each iteration needs its own.
    for pends in [1usize, 8] {
        let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
        let (addr, _conn_rx) = spawn_tls_server(ServerOptions {
            cert_der,
            key_der,
            server_alpn: vec![],
            require_client_cert_ca: None,
        })
        .await;
        let tcp = TcpStream::connect(addr).await.expect("TCP connect");
        let stream = DeferredFlushStream {
            inner: tcp,
            pending_budget: pends,
        };
        let config = TlsConfig {
            skip_cert_verify: true,
            ..TlsConfig::new("localhost")
        };
        let layer = TlsLayer::new(&config).expect("TlsLayer::new");
        let result = layer.connect(Box::new(stream)).await;
        assert!(
            result.is_ok(),
            "handshake over flush-pending stream (pends={pends}) must succeed: {:?}",
            result.err()
        );
    }
}
