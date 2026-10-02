//! Browser-shaped ClientHello encoding for the REALITY handshake (issue #708).
//!
//! REALITY's whole point is that the handshake a censor sees is the one a
//! browser would send to the cover site, so the ClientHello has to carry a
//! real browser's cipher list, extension set and order, GREASE and padding —
//! not a minimal one-suite hello.  The REALITY client encodes its own hello
//! (`reality_tls.rs`), so shaping is pure byte work: this module owns the
//! profile tables and the encoder, and knows nothing about the REALITY
//! `session_id` seal beyond leaving the 32-byte field zeroed for it.
//!
//! The profile tables are transcribed from uTLS `u_parrots.go`
//! (refraction-networking/utls, BSD-3-Clause; the metacubex fork mihomo
//! ships) and deliberately match the versions the BoringSSL backend parrots
//! for plain TLS (`tls/boring_backend.rs`): `chrome` is Chrome 120,
//! `firefox` Firefox 120, `safari` Safari 16.0, `ios` iOS 14, `edge`
//! Edge 85.  None of them offers a hybrid post-quantum share, so the
//! handshake only ever has to complete X25519.

use crate::{Result, TransportError};

/// Marks a slot the encoder fills with a per-hello GREASE value
/// (RFC 8701); which value depends on the list the slot sits in.
const GREASE: u16 = 0x0a0a;

const GROUP_X25519: u16 = 0x001d;
const GROUP_P256: u16 = 0x0017;

const EXT_PADDING: u16 = 21;

/// HPKE AEAD ids offered by a GREASE `encrypted_client_hello`.
const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;

/// One ClientHello extension, in the shape the profile tables need.
#[derive(Clone, Copy)]
enum Ext {
    /// GREASE extension: the first is empty, the second carries one zero
    /// byte and a different GREASE id (BoringSSL's rule).
    Grease,
    ServerName,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedGroups(&'static [u16]),
    PointFormats,
    SessionTicket,
    Alpn,
    StatusRequest,
    SignatureAlgorithms(&'static [u16]),
    Sct,
    /// `key_share`: an optional GREASE entry, X25519, then optionally a
    /// decoy P-256 entry (Firefox sends both).
    KeyShare {
        grease: bool,
        p256: bool,
    },
    PskModes,
    SupportedVersions(&'static [u16]),
    /// `compress_certificate` advertising one algorithm.
    CompressCertificate(u16),
    /// Chrome's ALPS (`application_settings`, 17513) for `h2`.
    ApplicationSettings,
    /// GREASE `encrypted_client_hello`: one AEAD and one payload length
    /// are picked per hello from the candidates.
    GreaseEch {
        aeads: &'static [u16],
        payload_lens: &'static [u16],
    },
    DelegatedCredentials(&'static [u16]),
    RecordSizeLimit(u16),
    /// BoringSSL-style padding to 512 bytes; emitted only when the
    /// unpadded hello lands in the 256..512 range.
    Padding,
}

impl Ext {
    /// GREASE and padding keep their position under Chrome's shuffle.
    fn is_pinned(self) -> bool {
        matches!(self, Self::Grease | Self::Padding)
    }
}

struct Spec {
    cipher_suites: &'static [u16],
    extensions: &'static [Ext],
    /// Randomise extension order per hello (Chrome ≥ 106).
    shuffle: bool,
}

const CHROME_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// Chrome's TLS 1.3 + TLS 1.2 suites (shared by Chrome 120 and Edge 85).
const CHROME_CIPHERS: &[u16] = &[
    GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];

/// `HelloChrome_120`.
const CHROME: Spec = Spec {
    cipher_suites: CHROME_CIPHERS,
    extensions: &[
        Ext::Grease,
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups(&[GREASE, GROUP_X25519, GROUP_P256, 0x0018]),
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms(CHROME_SIGALGS),
        Ext::Sct,
        Ext::KeyShare {
            grease: true,
            p256: false,
        },
        Ext::PskModes,
        Ext::SupportedVersions(&[GREASE, 0x0304, 0x0303]),
        Ext::CompressCertificate(2), // brotli
        Ext::ApplicationSettings,
        Ext::GreaseEch {
            aeads: &[HPKE_AEAD_AES_128_GCM],
            payload_lens: &[144, 176, 208, 240],
        },
        Ext::Grease,
        Ext::Padding,
    ],
    shuffle: true,
};

/// `HelloEdge_85` (Chrome 83 base: no shuffle, no ALPS / ECH GREASE).
const EDGE: Spec = Spec {
    cipher_suites: CHROME_CIPHERS,
    extensions: &[
        Ext::Grease,
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups(&[GREASE, GROUP_X25519, GROUP_P256, 0x0018]),
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms(CHROME_SIGALGS),
        Ext::Sct,
        Ext::KeyShare {
            grease: true,
            p256: false,
        },
        Ext::PskModes,
        Ext::SupportedVersions(&[GREASE, 0x0304, 0x0303, 0x0302, 0x0301]),
        Ext::CompressCertificate(2), // brotli
        Ext::Grease,
        Ext::Padding,
    ],
    shuffle: false,
};

/// `HelloFirefox_120`.
const FIREFOX: Spec = Spec {
    cipher_suites: &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    extensions: &[
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups(&[GROUP_X25519, GROUP_P256, 0x0018, 0x0019, 0x0100, 0x0101]),
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::DelegatedCredentials(&[0x0403, 0x0503, 0x0603, 0x0203]),
        Ext::KeyShare {
            grease: false,
            p256: true,
        },
        Ext::SupportedVersions(&[0x0304, 0x0303]),
        Ext::SignatureAlgorithms(&[
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ]),
        Ext::PskModes,
        Ext::RecordSizeLimit(0x4001),
        Ext::GreaseEch {
            aeads: &[HPKE_AEAD_AES_128_GCM, HPKE_AEAD_CHACHA20_POLY1305],
            payload_lens: &[239],
        },
    ],
    shuffle: false,
};

/// Apple's signature algorithms (the duplicated `0x0805` is in the real
/// hello and in uTLS's table).
const APPLE_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const APPLE_GROUPS: &[u16] = &[GREASE, GROUP_X25519, GROUP_P256, 0x0018, 0x0019];

const APPLE_VERSIONS: &[u16] = &[GREASE, 0x0304, 0x0303, 0x0302, 0x0301];

/// `HelloSafari_16_0`.
const SAFARI: Spec = Spec {
    cipher_suites: &[
        GREASE, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a,
        0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
    ],
    extensions: &[
        Ext::Grease,
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups(APPLE_GROUPS),
        Ext::PointFormats,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms(APPLE_SIGALGS),
        Ext::Sct,
        Ext::KeyShare {
            grease: true,
            p256: false,
        },
        Ext::PskModes,
        Ext::SupportedVersions(APPLE_VERSIONS),
        Ext::CompressCertificate(1), // zlib
        Ext::Grease,
        Ext::Padding,
    ],
    shuffle: false,
};

/// `HelloIOS_14`.
const IOS: Spec = Spec {
    cipher_suites: &[
        GREASE, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024,
        0xc023, 0xc00a, 0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c,
        0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
    ],
    extensions: &[
        Ext::Grease,
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups(APPLE_GROUPS),
        Ext::PointFormats,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms(APPLE_SIGALGS),
        Ext::Sct,
        Ext::KeyShare {
            grease: true,
            p256: false,
        },
        Ext::PskModes,
        Ext::SupportedVersions(APPLE_VERSIONS),
        Ext::Grease,
        Ext::Padding,
    ],
    shuffle: false,
};

/// The browser a REALITY ClientHello imitates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HelloProfile {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Edge,
}

impl HelloProfile {
    /// Resolve a `client-fingerprint` value.
    ///
    /// `random` picks once, with the same weights as the BoringSSL backend
    /// (chrome 6 / safari 3 / ios 2 / firefox 1).  A REALITY hello that is
    /// not browser-shaped defeats the transport, so every other value —
    /// unset, `none`, a profile this build has no table for, or one that
    /// cannot speak TLS 1.3 (`android` is OkHttp's TLS 1.2 hello) — falls
    /// back to `chrome`, with a warning when a named profile was requested.
    pub(crate) fn resolve(fingerprint: Option<&str>) -> Self {
        match fingerprint {
            Some("chrome" | "chrome120") | None => Self::Chrome,
            Some("firefox" | "firefox120") => Self::Firefox,
            Some("safari" | "safari16") => Self::Safari,
            Some("ios") => Self::Ios,
            Some("edge") => Self::Edge,
            Some("random") => match rand::random::<u8>() % 12 {
                0..=5 => Self::Chrome,
                6..=8 => Self::Safari,
                9..=10 => Self::Ios,
                _ => Self::Firefox,
            },
            Some(other) => {
                tracing::warn!(
                    "client-fingerprint=\"{other}\" has no TLS 1.3 profile for Reality TLS; \
                     using \"chrome\""
                );
                Self::Chrome
            }
        }
    }

    fn spec(self) -> &'static Spec {
        match self {
            Self::Chrome => &CHROME,
            Self::Firefox => &FIREFOX,
            Self::Safari => &SAFARI,
            Self::Ios => &IOS,
            Self::Edge => &EDGE,
        }
    }
}

/// Per-hello GREASE values, one per list kind (BoringSSL's
/// `ssl_grease_index_t`).
struct GreaseValues {
    cipher: u16,
    group: u16,
    extension1: u16,
    extension2: u16,
    version: u16,
}

impl GreaseValues {
    fn random() -> Self {
        let seed: [u8; 5] = rand::random();
        let value = |b: u8| u16::from((b & 0xf0) | 0x0a) * 0x0101;
        let extension1 = value(seed[2]);
        let mut extension2 = value(seed[3]);
        if extension2 == extension1 {
            extension2 ^= 0x1010;
        }
        Self {
            cipher: value(seed[0]),
            group: value(seed[1]),
            extension1,
            extension2,
            version: value(seed[4]),
        }
    }
}

fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Append `values` as a `u16`-length-prefixed list, swapping the GREASE
/// placeholder for `grease`.
fn put_u16_list(values: &[u16], grease: u16, out: &mut Vec<u8>) {
    put_u16((values.len() * 2) as u16, out);
    for &value in values {
        put_u16(if value == GREASE { grease } else { value }, out);
    }
}

fn server_name_data(server_name: &str) -> Result<Vec<u8>> {
    // name_type(1) + length(2) + name, inside a u16 list.
    if server_name.len() > usize::from(u16::MAX) - 3 {
        return Err(TransportError::Config("SNI is too long".into()));
    }
    let mut out = Vec::with_capacity(5 + server_name.len());
    put_u16((server_name.len() + 3) as u16, &mut out);
    out.push(0);
    put_u16(server_name.len() as u16, &mut out);
    out.extend_from_slice(server_name.as_bytes());
    Ok(out)
}

fn alpn_data<S: AsRef<str>>(protocols: &[S]) -> Result<Vec<u8>> {
    let mut list = Vec::new();
    for protocol in protocols {
        let bytes = protocol.as_ref().as_bytes();
        let len = u8::try_from(bytes.len()).map_err(|_| {
            TransportError::Config(format!(
                "ALPN protocol id '{}' is too long",
                protocol.as_ref()
            ))
        })?;
        list.push(len);
        list.extend_from_slice(bytes);
    }
    let list_len = u16::try_from(list.len())
        .map_err(|_| TransportError::Config("ALPN protocol list is too long".into()))?;
    let mut out = Vec::with_capacity(2 + list.len());
    put_u16(list_len, &mut out);
    out.extend_from_slice(&list);
    Ok(out)
}

/// A fresh P-256 public key (uncompressed point) for the decoy share
/// Firefox sends next to X25519.  The private half is dropped: a REALITY
/// server authenticates on the X25519 share, and a peer that picks P-256
/// anyway is rejected by `parse_server_hello`.
fn p256_decoy_share() -> Result<Vec<u8>> {
    use boring::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };
    let err = |e: boring::error::ErrorStack| {
        TransportError::Tls(format!("Reality TLS: P-256 key share: {e}"))
    };
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(err)?;
    let key = EcKey::generate(&group).map_err(err)?;
    let mut ctx = BigNumContext::new().map_err(err)?;
    key.public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(err)
}

fn grease_ech_data(aeads: &[u16], payload_lens: &[u16]) -> Vec<u8> {
    let aead = aeads[rand::random_range(0..aeads.len())];
    let payload_len = usize::from(payload_lens[rand::random_range(0..payload_lens.len())]);
    let mut out = Vec::with_capacity(10 + 32 + payload_len);
    out.push(0); // ECHClientHelloType: outer
    put_u16(0x0001, &mut out); // HKDF-SHA256
    put_u16(aead, &mut out);
    out.push(rand::random()); // config_id
    put_u16(32, &mut out); // X25519 encapsulated key
    out.extend_from_slice(&rand::random::<[u8; 32]>());
    put_u16(payload_len as u16, &mut out);
    let start = out.len();
    out.resize(start + payload_len, 0);
    rand::fill(&mut out[start..]);
    out
}

/// Everything a hello carries that is not part of the browser profile.
pub(crate) struct HelloParams<'a> {
    pub(crate) server_name: &'a str,
    /// ALPN protocols from the proxy config; empty means the profile's
    /// own `h2`, `http/1.1` (uTLS behaviour).
    pub(crate) alpn: &'a [String],
    pub(crate) random: &'a [u8; 32],
    pub(crate) x25519_public: &'a [u8; 32],
}

/// Encode a framed ClientHello handshake message shaped like `profile`.
///
/// The 32-byte `session_id` at `hello[39..71]` is left zeroed for the
/// REALITY seal, which authenticates exactly these bytes as AAD — so the
/// caller must not change anything else afterwards.
pub(crate) fn build_client_hello(
    profile: HelloProfile,
    params: &HelloParams<'_>,
) -> Result<Vec<u8>> {
    let spec = profile.spec();
    let grease = GreaseValues::random();

    let mut order: Vec<Ext> = spec.extensions.to_vec();
    if spec.shuffle {
        shuffle_unpinned(&mut order);
    }

    let mut body = Vec::with_capacity(1024);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(params.random);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);
    put_u16_list(spec.cipher_suites, grease.cipher, &mut body);
    body.extend_from_slice(&[1, 0]); // compression: null only

    let mut exts = Vec::with_capacity(768);
    let mut grease_seen = false;
    for ext in order {
        let (typ, data): (u16, Vec<u8>) = match ext {
            Ext::Grease => {
                let first = !grease_seen;
                grease_seen = true;
                if first {
                    (grease.extension1, Vec::new())
                } else {
                    (grease.extension2, vec![0])
                }
            }
            Ext::ServerName => (0, server_name_data(params.server_name)?),
            Ext::ExtendedMasterSecret => (23, Vec::new()),
            Ext::RenegotiationInfo => (0xff01, vec![0]),
            Ext::SupportedGroups(groups) => {
                let mut data = Vec::with_capacity(2 + groups.len() * 2);
                put_u16_list(groups, grease.group, &mut data);
                (10, data)
            }
            Ext::PointFormats => (11, vec![1, 0]),
            Ext::SessionTicket => (35, Vec::new()),
            Ext::Alpn => {
                let data = if params.alpn.is_empty() {
                    alpn_data(&["h2", "http/1.1"])?
                } else {
                    alpn_data(params.alpn)?
                };
                (16, data)
            }
            Ext::StatusRequest => (5, vec![1, 0, 0, 0, 0]),
            Ext::SignatureAlgorithms(algs) => {
                let mut data = Vec::with_capacity(2 + algs.len() * 2);
                put_u16_list(algs, GREASE, &mut data);
                (13, data)
            }
            Ext::Sct => (18, Vec::new()),
            Ext::KeyShare {
                grease: with_grease,
                p256,
            } => {
                let mut shares = Vec::with_capacity(128);
                if with_grease {
                    put_u16(grease.group, &mut shares);
                    put_u16(1, &mut shares);
                    shares.push(0);
                }
                put_u16(GROUP_X25519, &mut shares);
                put_u16(32, &mut shares);
                shares.extend_from_slice(params.x25519_public);
                if p256 {
                    let point = p256_decoy_share()?;
                    put_u16(GROUP_P256, &mut shares);
                    put_u16(point.len() as u16, &mut shares);
                    shares.extend_from_slice(&point);
                }
                let mut data = Vec::with_capacity(2 + shares.len());
                put_u16(shares.len() as u16, &mut data);
                data.extend_from_slice(&shares);
                (51, data)
            }
            Ext::PskModes => (45, vec![1, 1]),
            Ext::SupportedVersions(versions) => {
                let mut data = Vec::with_capacity(1 + versions.len() * 2);
                data.push((versions.len() * 2) as u8);
                for &version in versions {
                    put_u16(
                        if version == GREASE {
                            grease.version
                        } else {
                            version
                        },
                        &mut data,
                    );
                }
                (43, data)
            }
            Ext::CompressCertificate(alg) => {
                let alg = alg.to_be_bytes();
                (27, vec![2, alg[0], alg[1]])
            }
            Ext::ApplicationSettings => (17513, vec![0, 3, 2, b'h', b'2']),
            Ext::GreaseEch {
                aeads,
                payload_lens,
            } => (0xfe0d, grease_ech_data(aeads, payload_lens)),
            Ext::DelegatedCredentials(algs) => {
                let mut data = Vec::with_capacity(2 + algs.len() * 2);
                put_u16_list(algs, GREASE, &mut data);
                (34, data)
            }
            Ext::RecordSizeLimit(limit) => (28, limit.to_be_bytes().to_vec()),
            Ext::Padding => {
                // BoringSSL pads the whole handshake message (4-byte header
                // included) up to 512 bytes when it would otherwise land in
                // 256..512; `+ 2` is the extensions-block length prefix.
                let unpadded = 4 + body.len() + 2 + exts.len();
                if !(0x100..0x200).contains(&unpadded) {
                    continue;
                }
                let padding = (0x200 - unpadded).saturating_sub(4).max(1);
                (EXT_PADDING, vec![0; padding])
            }
        };
        put_u16(typ, &mut exts);
        put_u16(data.len() as u16, &mut exts);
        exts.extend_from_slice(&data);
    }

    let exts_len = u16::try_from(exts.len())
        .map_err(|_| TransportError::Config("ClientHello extensions are too long".into()))?;
    put_u16(exts_len, &mut body);
    body.extend_from_slice(&exts);

    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(1); // HandshakeType: client_hello
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    Ok(hello)
}

/// Fisher–Yates over the extensions that are not position-pinned.
fn shuffle_unpinned(exts: &mut [Ext]) {
    let movable: Vec<usize> = (0..exts.len()).filter(|&i| !exts[i].is_pinned()).collect();
    for i in (1..movable.len()).rev() {
        let j = rand::random_range(0..=i);
        exts.swap(movable[i], movable[j]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Parsed {
        cipher_suites: Vec<u16>,
        /// `(type, data)` in wire order.
        extensions: Vec<(u16, Vec<u8>)>,
    }

    fn u16_at(buf: &[u8], pos: usize) -> u16 {
        u16::from_be_bytes([buf[pos], buf[pos + 1]])
    }

    /// Strict parse: every length prefix must account for the whole
    /// message, so an encoder slip surfaces here rather than at a server.
    fn parse(hello: &[u8]) -> Parsed {
        assert_eq!(hello[0], 1);
        let body_len = usize::from(hello[1]) << 16 | usize::from(u16_at(hello, 2));
        assert_eq!(hello.len(), 4 + body_len);
        assert_eq!(&hello[4..6], &[0x03, 0x03]);
        assert_eq!(hello[38], 32);
        assert_eq!(
            &hello[39..71],
            &[0u8; 32],
            "session_id is left for the seal"
        );
        let mut pos = 71;
        let cs_len = usize::from(u16_at(hello, pos));
        pos += 2;
        let cipher_suites = hello[pos..pos + cs_len]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        pos += cs_len;
        assert_eq!(&hello[pos..pos + 2], &[1, 0]);
        pos += 2;
        let exts_len = usize::from(u16_at(hello, pos));
        pos += 2;
        assert_eq!(pos + exts_len, hello.len());
        let mut extensions = Vec::new();
        while pos < hello.len() {
            let typ = u16_at(hello, pos);
            let len = usize::from(u16_at(hello, pos + 2));
            extensions.push((typ, hello[pos + 4..pos + 4 + len].to_vec()));
            pos += 4 + len;
        }
        assert_eq!(pos, hello.len());
        Parsed {
            cipher_suites,
            extensions,
        }
    }

    fn is_grease(value: u16) -> bool {
        value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
    }

    fn build(profile: HelloProfile, alpn: &[String]) -> Vec<u8> {
        build_client_hello(
            profile,
            &HelloParams {
                server_name: "example.com",
                alpn,
                random: &[7u8; 32],
                x25519_public: &[3u8; 32],
            },
        )
        .expect("client hello")
    }

    /// Chrome's extensions without the trailing padding, which BoringSSL
    /// appends only when a short ECH GREASE payload leaves the hello
    /// under 512 bytes.
    fn chrome_unpadded(parsed: &Parsed) -> &[(u16, Vec<u8>)] {
        match parsed.extensions.split_last() {
            Some(((EXT_PADDING, _), rest)) => rest,
            _ => &parsed.extensions,
        }
    }

    fn ext_ids(parsed: &Parsed) -> Vec<u16> {
        parsed
            .extensions
            .iter()
            .map(|(typ, _)| if is_grease(*typ) { GREASE } else { *typ })
            .collect()
    }

    fn ext(parsed: &Parsed, typ: u16) -> &[u8] {
        &parsed
            .extensions
            .iter()
            .find(|(t, _)| *t == typ)
            .unwrap_or_else(|| panic!("extension {typ} missing"))
            .1
    }

    /// JA3-style extension order for the profiles that do not shuffle —
    /// the wire order must be the uTLS table's order.
    #[test]
    fn fixed_profiles_emit_reference_extension_order() {
        let cases: [(HelloProfile, &[u16]); 4] = [
            (
                HelloProfile::Firefox,
                &[
                    0, 23, 0xff01, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 0xfe0d,
                ],
            ),
            (
                HelloProfile::Safari,
                &[
                    GREASE, 0, 23, 0xff01, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, GREASE, 21,
                ],
            ),
            (
                HelloProfile::Ios,
                &[
                    GREASE, 0, 23, 0xff01, 10, 11, 16, 5, 13, 18, 51, 45, 43, GREASE, 21,
                ],
            ),
            (
                HelloProfile::Edge,
                &[
                    GREASE, 0, 23, 0xff01, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, GREASE, 21,
                ],
            ),
        ];
        for (profile, expected) in cases {
            let parsed = parse(&build(profile, &[]));
            assert_eq!(ext_ids(&parsed), expected, "{profile:?}");
        }
    }

    #[test]
    fn chrome_offers_the_chrome_cipher_list_with_grease_first() {
        let parsed = parse(&build(HelloProfile::Chrome, &[]));
        assert!(is_grease(parsed.cipher_suites[0]));
        assert_eq!(parsed.cipher_suites[1..], CHROME_CIPHERS[1..]);
    }

    /// Chrome's GREASE extensions bracket the hello: the first is empty,
    /// the last carries one zero byte, and the two ids differ.
    #[test]
    fn chrome_grease_extensions_follow_boringssl_rules() {
        for _ in 0..64 {
            let parsed = parse(&build(HelloProfile::Chrome, &[]));
            let exts = chrome_unpadded(&parsed);
            let (first, first_data) = &exts[0];
            let (last, last_data) = exts.last().unwrap();
            assert!(is_grease(*first) && is_grease(*last));
            assert_ne!(first, last);
            assert!(first_data.is_empty());
            assert_eq!(last_data, &[0]);

            let groups = ext(&parsed, 10);
            assert!(is_grease(u16_at(groups, 2)));
            let versions = ext(&parsed, 43);
            assert!(is_grease(u16_at(versions, 1)));
            // key_share: GREASE entry (same value as the group list's),
            // then the real X25519 share.
            let shares = ext(&parsed, 51);
            assert_eq!(u16_at(shares, 2), u16_at(groups, 2));
            assert_eq!(&shares[4..7], &[0, 1, 0]);
            assert_eq!(u16_at(shares, 7), GROUP_X25519);
            assert_eq!(&shares[11..43], &[3u8; 32]);
        }
    }

    /// Chrome ≥ 106 permutes its extensions per connection: the set is
    /// stable, the order is not, and GREASE stays first and last.
    #[test]
    fn chrome_shuffles_extensions_but_keeps_the_set() {
        let mut expected: Vec<u16> = vec![
            GREASE, 0, 23, 0xff01, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 0xfe0d, GREASE,
        ];
        expected.sort_unstable();

        let mut orders = std::collections::HashSet::new();
        for _ in 0..32 {
            let mut ids = ext_ids(&parse(&build(HelloProfile::Chrome, &[])));
            if ids.last() == Some(&EXT_PADDING) {
                ids.pop();
            }
            assert_eq!(ids[0], GREASE);
            assert_eq!(*ids.last().unwrap(), GREASE);
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, expected);
            orders.insert(ids);
        }
        assert!(orders.len() > 1, "extension order never changed");
    }

    /// Profiles whose unpadded hello is under 512 bytes are padded to
    /// exactly 512 (BoringSSL / Secure Transport behaviour).  Chrome's
    /// ECH GREASE usually pushes it past 512; when it does not, the same
    /// rule pads it, so a Chrome hello is never shorter.
    #[test]
    fn padding_rounds_short_hellos_up_to_512_bytes() {
        for profile in [HelloProfile::Safari, HelloProfile::Ios, HelloProfile::Edge] {
            let hello = build(profile, &[]);
            assert_eq!(hello.len(), 512, "{profile:?}");
            let parsed = parse(&hello);
            assert!(ext(&parsed, EXT_PADDING).iter().all(|b| *b == 0));
        }
        for _ in 0..64 {
            let chrome = build(HelloProfile::Chrome, &[]);
            assert!(chrome.len() >= 512);
            let padded = ext_ids(&parse(&chrome)).contains(&EXT_PADDING);
            assert_eq!(padded, chrome.len() == 512);
        }
    }

    #[test]
    fn firefox_sends_x25519_and_a_valid_p256_share() {
        let parsed = parse(&build(HelloProfile::Firefox, &[]));
        let shares = ext(&parsed, 51);
        assert_eq!(usize::from(u16_at(shares, 0)), shares.len() - 2);
        assert_eq!(u16_at(shares, 2), GROUP_X25519);
        assert_eq!(&shares[6..38], &[3u8; 32]);
        assert_eq!(u16_at(shares, 38), GROUP_P256);
        assert_eq!(u16_at(shares, 40), 65);
        assert_eq!(shares[42], 0x04, "uncompressed point");
        assert_eq!(shares.len(), 42 + 65);
        assert!(!parsed.cipher_suites.iter().any(|c| is_grease(*c)));
    }

    #[test]
    fn alpn_defaults_to_the_browser_list_and_honours_config() {
        let parsed = parse(&build(HelloProfile::Chrome, &[]));
        assert_eq!(ext(&parsed, 16), b"\x00\x0c\x02h2\x08http/1.1");
        let parsed = parse(&build(HelloProfile::Chrome, &["h2".to_string()]));
        assert_eq!(ext(&parsed, 16), b"\x00\x03\x02h2");
    }

    #[test]
    fn server_name_extension_carries_the_host() {
        let parsed = parse(&build(HelloProfile::Safari, &[]));
        assert_eq!(ext(&parsed, 0), b"\x00\x0e\x00\x00\x0bexample.com");
    }

    #[test]
    fn grease_ech_matches_the_profile_shape() {
        for _ in 0..32 {
            let parsed = parse(&build(HelloProfile::Chrome, &[]));
            let ech = ext(&parsed, 0xfe0d);
            assert_eq!(
                &ech[..5],
                &[0, 0, 1, 0, 1],
                "outer, HKDF-SHA256, AES-128-GCM"
            );
            assert_eq!(u16_at(ech, 6), 32);
            let payload_len = u16_at(ech, 40);
            assert!([144, 176, 208, 240].contains(&payload_len));
            assert_eq!(ech.len(), 42 + usize::from(payload_len));
        }
        let parsed = parse(&build(HelloProfile::Firefox, &[]));
        assert_eq!(u16_at(ext(&parsed, 0xfe0d), 40), 239);
    }

    #[test]
    fn resolve_maps_names_and_falls_back_to_chrome() {
        assert_eq!(HelloProfile::resolve(None), HelloProfile::Chrome);
        assert_eq!(HelloProfile::resolve(Some("chrome")), HelloProfile::Chrome);
        assert_eq!(
            HelloProfile::resolve(Some("firefox")),
            HelloProfile::Firefox
        );
        assert_eq!(HelloProfile::resolve(Some("safari")), HelloProfile::Safari);
        assert_eq!(HelloProfile::resolve(Some("ios")), HelloProfile::Ios);
        assert_eq!(HelloProfile::resolve(Some("edge")), HelloProfile::Edge);
        // OkHttp's hello is TLS 1.2-only; REALITY needs TLS 1.3.
        assert_eq!(HelloProfile::resolve(Some("android")), HelloProfile::Chrome);
        assert_eq!(HelloProfile::resolve(Some("qq")), HelloProfile::Chrome);
    }
}
