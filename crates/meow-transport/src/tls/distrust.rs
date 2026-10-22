//! Certificates meow refuses to chain through even when a trusted root
//! signed them.
//!
//! Browsers block a compromised intermediate before its root is removed
//! (Firefox through OneCRL, Chrome through CRLSets). meow checks neither OCSP,
//! CRLs nor Certificate Transparency, so without this list an intermediate
//! stays trusted for as long as any root in the verify store vouches for it:
//! the Mozilla bundle, a user's `ca` / `ca-str`, or a cross-sign from another
//! root.
//!
//! Entries are SHA-256 digests of the DER `SubjectPublicKeyInfo`, not of the
//! certificate. Blocking the key covers every certificate issued for it, so
//! cross-signs and re-issues need no extra entries.
//!
//! Every chain-verifying TLS client installs [`verify_callback`]: the
//! `TlsLayer` connector, the hysteria2 and TrustTunnel QUIC configs, and
//! restls checks [`chain_is_distrusted`] after its own verification. A pinned
//! certificate `fingerprint` replaces CA validation entirely and is not
//! filtered.

use boring::hash::{hash, MessageDigest};
use boring::stack::StackRef;
use boring::x509::{X509Ref, X509StoreContextRef, X509VerifyError, X509};

/// eMudhra's P-384 "G3B" / "G3C" intermediates, generated on 30 April 2025
/// with private keys small enough to recover from the certificates (Mozilla
/// bug 2083449, <https://emudhra.we-have-a-problem.com/>). Each key has two
/// certificates: one issued by emSign Root TLS CA - G3 or emSign Root CS
/// CA - G3, reached through emSign ECC Root CA - G3, and one cross-signed by
/// Sectigo's AAA Certificate Services. webpki-root-certs 1.0.10 no longer
/// trusts emSign ECC Root CA - G3 (#785), and AAA Certificate Services was
/// never in it, so these entries guard the remaining paths.
const DISTRUSTED_SPKI_SHA256: [[u8; 32]; 8] = [
    // EM DV TLS CA - G3B
    [
        0xeb, 0xed, 0x64, 0x75, 0xc2, 0xc2, 0xd8, 0x0f, 0xcb, 0x19, 0x9f, 0x3f, 0xe8, 0xdd, 0x6e,
        0x6b, 0x3c, 0xe6, 0x0b, 0x77, 0xeb, 0x15, 0xd4, 0xe4, 0x2c, 0x3d, 0xec, 0x0c, 0x6f, 0x5b,
        0x51, 0x05,
    ],
    // EM DV TLS CA - G3C
    [
        0x49, 0xdd, 0x35, 0x3d, 0xc2, 0xb9, 0x19, 0xa3, 0x77, 0x06, 0x45, 0x11, 0x7d, 0x0e, 0x60,
        0xc1, 0x61, 0x15, 0xe7, 0xd1, 0xbc, 0x25, 0x9e, 0xef, 0xe7, 0x34, 0xb0, 0x0e, 0xa4, 0x34,
        0xfe, 0x5f,
    ],
    // EM EV TLS CA - G3B
    [
        0xe0, 0x25, 0x4c, 0x7f, 0xcd, 0xc2, 0x65, 0xe2, 0xf0, 0xf8, 0xa4, 0x28, 0xda, 0xbb, 0x75,
        0xab, 0x4a, 0xe0, 0x39, 0xb4, 0x87, 0x2d, 0x62, 0xf5, 0xee, 0x57, 0xf0, 0x87, 0x7d, 0x5a,
        0x8a, 0x41,
    ],
    // EM EV TLS CA - G3C
    [
        0x5c, 0x06, 0x60, 0xa2, 0xb1, 0x64, 0x91, 0x0d, 0x8f, 0xf5, 0x89, 0xc1, 0x8e, 0x14, 0x55,
        0x2e, 0x9e, 0x0e, 0xc2, 0x37, 0xdc, 0xef, 0xe2, 0xcb, 0x73, 0x6d, 0x41, 0xa4, 0x81, 0x1f,
        0x81, 0xa0,
    ],
    // EM OV CS CA - G3B
    [
        0xec, 0x4f, 0xfa, 0x1a, 0xd0, 0xac, 0x88, 0x08, 0x13, 0x14, 0xb7, 0xaa, 0xff, 0xef, 0x6a,
        0x91, 0xf9, 0x7c, 0xd5, 0x72, 0x91, 0xbb, 0x5b, 0xa6, 0x86, 0xc5, 0x41, 0x5f, 0x5e, 0xb4,
        0xf6, 0xb6,
    ],
    // EM OV CS CA - G3C
    [
        0x92, 0xc0, 0x63, 0xd6, 0x7e, 0x8f, 0x14, 0xdb, 0x71, 0xd2, 0x88, 0xe1, 0x12, 0x66, 0xff,
        0xda, 0xf6, 0x9c, 0xbf, 0x11, 0x5f, 0x7b, 0xab, 0x14, 0xf3, 0xbc, 0x2f, 0x68, 0xd2, 0x5e,
        0x0e, 0x30,
    ],
    // EM OV TLS CA - G3B
    [
        0x43, 0xbf, 0xfa, 0x19, 0xd6, 0xef, 0x65, 0x14, 0x51, 0xf6, 0x84, 0x1e, 0x01, 0x99, 0x31,
        0xe9, 0x6f, 0x6f, 0x2e, 0xae, 0xff, 0x28, 0xab, 0x4b, 0x6f, 0x1c, 0xe4, 0x57, 0x6d, 0xe2,
        0x71, 0x7b,
    ],
    // EM OV TLS CA - G3C
    [
        0x63, 0xec, 0xef, 0xee, 0x43, 0x1d, 0x49, 0x52, 0x3b, 0xc1, 0x13, 0x6c, 0x4e, 0x72, 0xd0,
        0x20, 0x6a, 0x47, 0x70, 0x86, 0xca, 0xf6, 0x06, 0xcd, 0x5c, 0xf0, 0x25, 0x68, 0x6c, 0x10,
        0x9c, 0xf8,
    ],
];

/// Whether `cert`'s public key is on the distrust list.
///
/// A key that cannot be parsed is reported as trusted: BoringSSL fails the
/// chain on it anyway (`X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY`).
pub fn is_distrusted(cert: &X509Ref) -> bool {
    let Ok(spki) = cert.public_key().and_then(|key| key.public_key_to_der()) else {
        return false;
    };
    hash(MessageDigest::sha256(), &spki)
        .is_ok_and(|digest| DISTRUSTED_SPKI_SHA256.iter().any(|d| d[..] == digest[..]))
}

/// Whether any certificate in a verified chain is distrusted.
pub fn chain_is_distrusted(chain: &StackRef<X509>) -> bool {
    chain.iter().any(is_distrusted)
}

/// `SSL_CTX_set_verify` callback: BoringSSL's result, except that a
/// distrusted certificate anywhere in the chain fails the handshake with
/// `X509_V_ERR_CERT_REVOKED`.
///
/// BoringSSL calls it once per chain certificate, root to leaf, after
/// checking that certificate, so every position is covered.
pub fn verify_callback(preverify_ok: bool, ctx: &mut X509StoreContextRef) -> bool {
    if ctx.current_cert().is_some_and(is_distrusted) {
        ctx.set_error(Err(X509VerifyError::CERT_REVOKED));
        return false;
    }
    preverify_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::x509::store::X509StoreBuilder;
    use boring::x509::verify::X509VerifyFlags;
    use boring::x509::X509StoreContext;

    fn compromised() -> Vec<X509> {
        let certs = X509::stack_from_pem(include_bytes!("testdata/emudhra-g3-compromised.pem"))
            .expect("fixture parses");
        assert_eq!(certs.len(), 16, "eight keys, two certificates each");
        certs
    }

    #[test]
    fn every_compromised_certificate_is_distrusted() {
        for cert in compromised() {
            assert!(
                is_distrusted(&cert),
                "{:?} not distrusted",
                cert.subject_name()
            );
        }
    }

    #[test]
    fn list_holds_exactly_the_compromised_keys() {
        let mut found: Vec<Vec<u8>> = compromised()
            .iter()
            .map(|c| {
                let der = c.public_key().unwrap().public_key_to_der().unwrap();
                hash(MessageDigest::sha256(), &der).unwrap().to_vec()
            })
            .collect();
        found.sort();
        found.dedup();
        let mut listed: Vec<Vec<u8>> = DISTRUSTED_SPKI_SHA256.iter().map(|d| d.to_vec()).collect();
        listed.sort();
        assert_eq!(found, listed);
    }

    #[test]
    fn mozilla_roots_are_not_distrusted() {
        for root in super::super::boring_backend::boring_roots() {
            assert!(!is_distrusted(root), "{:?} distrusted", root.subject_name());
        }
    }

    /// Verify `cert` against a store whose only anchor is `cert` itself
    /// (`PARTIAL_CHAIN`), so BoringSSL accepts it, then run the callback the
    /// way `internal_verify` does for the last chain certificate.
    fn verify_as_anchor(cert: &X509) -> (bool, boring::x509::X509VerifyResult) {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(cert.clone()).unwrap();
        store.set_flags(X509VerifyFlags::PARTIAL_CHAIN);
        let store = store.build();
        let chain = boring::stack::Stack::<X509>::new().unwrap();
        X509StoreContext::new()
            .unwrap()
            .init(&store, cert, &chain, |ctx| {
                assert!(
                    ctx.verify_cert()?,
                    "anchor must verify: {}",
                    ctx.verify_result().unwrap_err()
                );
                assert_eq!(
                    chain_is_distrusted(ctx.chain().unwrap()),
                    is_distrusted(cert)
                );
                let ok = verify_callback(true, ctx);
                Ok((ok, ctx.verify_result()))
            })
            .unwrap()
    }

    #[test]
    fn callback_rejects_a_chain_through_a_compromised_key() {
        for cert in compromised() {
            let (ok, err) = verify_as_anchor(&cert);
            assert!(!ok, "{:?} accepted", cert.subject_name());
            assert_eq!(err, Err(X509VerifyError::CERT_REVOKED));
        }
    }

    #[test]
    fn callback_passes_other_chains_through() {
        let root = super::super::boring_backend::boring_roots()[0].clone();
        assert_eq!(verify_as_anchor(&root), (true, Ok(())));
    }
}
