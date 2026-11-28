//! Controlled client-Finished data-plane tests for the REALITY v2 dial-first
//! mirror (spec `listener-vless-reality-v2.md` §7 Finished-reader contract,
//! §9 gate T4).
//!
//! The production end-to-end hit test relies on the production client's
//! natural record shaping, so it cannot control the compat CCS, the
//! fragmentation of the client Finished, its trailing zero padding, or the
//! coalescing of the first application record.  This file drives all of
//! them explicitly: the test client rewrites a captured production
//! ClientHello onto a key share whose private half it owns, reads the real
//! mirrored flight off the wire, recomputes the complete RFC 8446 / spec
//! §4.2 key schedule independently (sharing no code with the transport's
//! own derivation), and then writes a cryptographically valid client
//! Finished in whatever shape the case requires.  Nothing about the
//! Finished is faked: every positive byte stream passes the real AEAD and
//! the constant-time `verify_data` comparison in the mirrored handshake
//! completion path.
#![cfg(feature = "listener-vless")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use meow_listener::{
    VlessFallbackLimit, VlessListener, VlessListenerSpec, VlessRealityMimicSpec, VlessRealitySpec,
    VlessSecuritySpec, VlessUserSpec,
};
use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer};
use meow_transport::Transport;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

mod common;

const T: Duration = Duration::from_secs(8);
const ALICE: [u8; 16] = [0x11; 16];
const REALITY_PRIVATE: [u8; 32] = [0x42; 32];
const SHORT_ID: [u8; 8] = [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0];
/// REALITY ClientVer the production client reports (xray-core 26.10.31).
const REALITY_CLIENT_VERSION: [u8; 3] = [26, 10, 31];
/// Test-only synthetic client key-exchange private key.  The bytes are a
/// fixed seed so failures are reproducible; they never leave the test.
const CLIENT_X25519_PRIVATE: [u8; 32] = [0x77; 32];

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
const COMPAT_CCS: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
const HS_FINISHED: u8 = 0x14;
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const GROUP_X25519: u16 = 0x001d;
const EXT_KEY_SHARE: u16 = 0x0033;
const SHA256_LEN: usize = 32;
const FINISHED_LEN: usize = 4 + SHA256_LEN;

// ─── independent RFC 8446 / spec §4.2 key schedule (SHA-256 only) ─────────
//
// These helpers are deliberately a from-scratch implementation over the
// generic RustCrypto crates: they share no code with the transport's own
// derivation, so a divergence in either implementation fails the positive
// test instead of canceling out.

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_LEN] {
    hmac_sha256(salt, &[ikm])
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        previous = hmac_sha256(prk, &[&previous, info, &[counter]]).to_vec();
        out.extend_from_slice(&previous);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// RFC 8446 §7.1 HKDF-Expand-Label: `uint16(len) || "tls13 "+label (u8 len)
/// || context (u8 len)`.
fn expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    let full_label = [b"tls13 ".as_slice(), label].concat();
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

/// Derive-Secret with an already-hashed transcript context, output one hash
/// length — spec §4.2 `DS(secret,label,messages)` shape.
fn derive_secret(secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> [u8; SHA256_LEN] {
    expand_label(secret, label, transcript_hash, SHA256_LEN)
        .try_into()
        .expect("hash-length output")
}

fn sha256(parts: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn x25519(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*private, *public)
}

fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES)
}

fn reality_public_key() -> [u8; 32] {
    x25519_public(&REALITY_PRIVATE)
}

// ─── TLS 1.3 record protection (AES-128-GCM, the fixture's suite) ─────────

struct RecordKey {
    cipher: Aes128Gcm,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKey {
    fn from_secret(secret: &[u8]) -> Self {
        let key = expand_label(secret, b"key", &[], 16);
        let iv = expand_label(secret, b"iv", &[], 12);
        Self {
            cipher: Aes128Gcm::new_from_slice(&key).expect("AES-128 key length"),
            iv: iv.try_into().expect("TLS IV length"),
            seq: 0,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        for (dst, src) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *dst ^= src;
        }
        self.seq += 1;
        nonce
    }

    /// Seal `plaintext` as one `17 03 03` record: content, then the inner
    /// type byte, then zero padding — RFC 8446 §5.4 ordering.
    fn seal_with_padding(&mut self, inner_type: u8, plaintext: &[u8], pad: usize) -> Vec<u8> {
        let body_len = plaintext.len() + pad + 1;
        let record_len = body_len + 16;
        assert!(u16::try_from(record_len).is_ok(), "record length overflow");
        let mut header = [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 0];
        header[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        let nonce = self.next_nonce();
        let mut body = plaintext.to_vec();
        body.push(inner_type);
        body.resize(plaintext.len() + pad + 1, 0);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header, &mut body)
            .expect("test record seal");
        body.extend_from_slice(&tag);
        let mut out = header.to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// Open a record, strip trailing zero padding, and return the inner
    /// type with the content before it.
    fn open(&mut self, header: &[u8; 5], payload: &[u8]) -> (u8, Vec<u8>) {
        let split = payload.len() - 16;
        let (data, tag) = payload.split_at(split);
        let nonce = self.next_nonce();
        let mut body = data.to_vec();
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                header,
                &mut body,
                Tag::from_slice(tag),
            )
            .expect("server flight records must open under the mirrored keys");
        let type_pos = body
            .iter()
            .rposition(|byte| *byte != 0)
            .expect("server flight plaintext carries an inner type");
        let inner_type = body[type_pos];
        body.truncate(type_pos);
        (inner_type, body)
    }
}

// ─── controlled ClientHello ───────────────────────────────────────────────

/// Capture one production-shaped REALITY ClientHello wire record.  The
/// captured share/session-id are placeholders: both are rewritten below.
async fn capture_production_client_hello() -> Vec<u8> {
    let (client_end, mut server_end) = tokio::io::duplex(128 * 1024);
    let tls = TlsConfig {
        reality: Some(RealityConfig {
            public_key: reality_public_key(),
            short_id: SHORT_ID,
            support_x25519_mlkem768: false,
            protocol_clock: None,
        }),
        ..TlsConfig::new("localhost")
    };
    let layer = TlsLayer::new(&tls).expect("reality client layer");
    let task = tokio::spawn(async move { layer.connect(Box::new(client_end)).await });
    let mut head = [0u8; 5];
    server_end
        .read_exact(&mut head)
        .await
        .expect("read CH record head");
    let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let mut body = vec![0u8; len];
    server_end
        .read_exact(&mut body)
        .await
        .expect("read CH record body");
    task.abort();
    let mut wire = head.to_vec();
    wire.extend_from_slice(&body);
    wire
}

/// Rewrite the captured hello onto the controlled key share and re-seal the
/// REALITY session id.  Returns the exact wire bytes to send; the logical
/// handshake message is `wire[5..]`.
fn controlled_client_hello(wire: &[u8]) -> Vec<u8> {
    assert_eq!(wire[0], TLS_RECORD_HANDSHAKE, "single CH handshake record");
    let mut out = wire.to_vec();
    // Logical layout: type(1) len(3) version(2) random(32) sid_len(1) sid(32),
    // all inside the record body at offset 5.
    let logical = 5;
    assert_eq!(out[logical], 0x01, "first handshake message is ClientHello");
    let hello_len = (usize::from(out[logical + 1]) << 16)
        | (usize::from(out[logical + 2]) << 8)
        | usize::from(out[logical + 3]);
    assert_eq!(
        hello_len + 4 + 5,
        out.len(),
        "one record carries exactly one CH"
    );
    assert_eq!(out[logical + 38], 32, "REALITY session id length");

    // Walk extensions to find the standalone X25519 share entry.
    let mut pos = logical + 39 + 32;
    let cs_len = usize::from(u16::from_be_bytes([out[pos], out[pos + 1]]));
    pos += 2 + cs_len;
    let comp_len = usize::from(out[pos]);
    pos += 1 + comp_len;
    let exts_len = usize::from(u16::from_be_bytes([out[pos], out[pos + 1]]));
    pos += 2;
    let exts_end = pos + exts_len;
    assert_eq!(exts_end, out.len(), "extensions close at the CH end");
    let mut share_offset = None;
    while pos < exts_end {
        let ext_type = u16::from_be_bytes([out[pos], out[pos + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([out[pos + 2], out[pos + 3]]));
        let data_start = pos + 4;
        if ext_type == EXT_KEY_SHARE {
            let mut sp = data_start + 2; // client_shares total length
            let shares_end = data_start + ext_len;
            while sp < shares_end {
                let group = u16::from_be_bytes([out[sp], out[sp + 1]]);
                let key_len = usize::from(u16::from_be_bytes([out[sp + 2], out[sp + 3]]));
                if group == GROUP_X25519 {
                    assert_eq!(key_len, 32, "X25519 share length");
                    share_offset = Some(sp + 4);
                    break;
                }
                sp += 4 + key_len;
            }
            assert!(
                share_offset.is_some(),
                "CH carries a standalone X25519 share"
            );
            break;
        }
        pos = data_start + ext_len;
    }
    let share_offset = share_offset.expect("key_share extension present");

    // Replace the share in place: both keys are 32 bytes, so no length
    // field anywhere in the hello changes.
    let client_private = CLIENT_X25519_PRIVATE;
    let client_public = x25519_public(&client_private);
    out[share_offset..share_offset + 32].copy_from_slice(&client_public);

    // Re-seal the session id for the rewritten share.  The AAD is the
    // logical hello with the session-id bytes zeroed, exactly as sealed.
    let random_start = logical + 6;
    let auth_dh = x25519(&client_private, &reality_public_key());
    let prk = hkdf_extract(&out[random_start..random_start + 20], &auth_dh);
    let auth_key = hkdf_expand(&prk, b"REALITY", 32);
    let sid_start = logical + 39;
    let mut aad = out[logical..].to_vec();
    aad[39..71].fill(0);
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as u32;
    let mut plaintext = Vec::with_capacity(16);
    plaintext.extend_from_slice(&REALITY_CLIENT_VERSION);
    plaintext.push(0);
    plaintext.extend_from_slice(&unix.to_be_bytes());
    plaintext.extend_from_slice(&SHORT_ID);
    let cipher = Aes256Gcm::new_from_slice(&auth_key).expect("AuthKey length");
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&out[random_start + 20..random_start + 32]),
            &aad,
            &mut plaintext,
        )
        .expect("session id seal");
    plaintext.extend_from_slice(&tag);
    assert_eq!(plaintext.len(), 32);
    out[sid_start..sid_start + 32].copy_from_slice(&plaintext);
    out
}

// ─── mirrored flight consumption ──────────────────────────────────────────

struct ControlledSession {
    stream: TcpStream,
    /// Logical client Finished message (`0x14 || uint24(32) || verify_data`).
    client_finished: Vec<u8>,
    client_handshake: RecordKey,
    client_application: RecordKey,
    server_application: RecordKey,
}

async fn read_exact_or_timeout(stream: &mut TcpStream, buf: &mut [u8], what: &str) {
    timeout(T, stream.read_exact(buf))
        .await
        .unwrap_or_else(|_| panic!("timed out reading {what}"))
        .unwrap_or_else(|e| panic!("reading {what}: {e}"));
}

/// Parse the patched ServerHello out of its record and return the logical
/// message plus the server's ephemeral X25519 share.
fn parse_patched_server_hello(record: &[u8]) -> (Vec<u8>, [u8; 32], u16) {
    assert_eq!(
        record[0], TLS_RECORD_HANDSHAKE,
        "first flight record is handshake"
    );
    assert_eq!(&record[1..3], &[0x03, 0x03], "SH record version");
    let sh_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    assert_eq!(record.len(), 5 + sh_len, "SH record exact length");
    let sh = record[5..].to_vec();
    assert_eq!(sh[0], 0x02, "handshake type ServerHello");
    assert_ne!(
        &sh[4..36],
        &[0x66; 32],
        "the mirror patch must replace the fixture target random"
    );
    let mut pos = 4 + 2 + 32;
    let sid_len = usize::from(sh[pos]);
    pos += 1 + sid_len;
    let cipher = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
    pos += 2;
    assert_eq!(sh[pos], 0, "null compression");
    pos += 1;
    let exts_len = usize::from(u16::from_be_bytes([sh[pos], sh[pos + 1]]));
    pos += 2;
    let exts_end = pos + exts_len;
    let mut share = None;
    while pos < exts_end {
        let ext_type = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]));
        let data = &sh[pos + 4..pos + 4 + ext_len];
        if ext_type == EXT_KEY_SHARE {
            let group = u16::from_be_bytes([data[0], data[1]]);
            assert_eq!(group, GROUP_X25519, "fixture target selects X25519");
            let key_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
            assert_eq!(key_len, 32);
            share = Some(data[4..4 + 32].try_into().expect("share length"));
        }
        pos += 4 + ext_len;
    }
    (sh, share.expect("patched SH carries a key share"), cipher)
}

/// Drive the controlled handshake through the real mirrored flight: send
/// the rewritten CH, read the emitted SH/CCS/encrypted records off the
/// wire, decrypt the server flight with the independently derived keys,
/// verify the server's own Finished the way a real client must, and return
/// the state needed to shape the client Finished.
async fn controlled_handshake(port: u16) -> ControlledSession {
    let ch_wire = controlled_client_hello(&capture_production_client_hello().await);
    let logical_ch = ch_wire[5..].to_vec();

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect listener");
    stream
        .write_all(&ch_wire)
        .await
        .expect("write controlled ClientHello");
    stream.flush().await.expect("flush ClientHello");

    // The emitted wire starts with exactly one patched SH record.
    let mut head = [0u8; 5];
    read_exact_or_timeout(&mut stream, &mut head, "patched SH record head").await;
    let sh_len = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let mut sh_body = vec![0u8; sh_len];
    read_exact_or_timeout(&mut stream, &mut sh_body, "patched SH record body").await;
    let mut sh_record = head.to_vec();
    sh_record.extend_from_slice(&sh_body);
    let (patched_sh, server_share, cipher) = parse_patched_server_hello(&sh_record);
    assert_eq!(
        cipher, TLS_AES_128_GCM_SHA256,
        "fixture target picks the SHA-256 suite"
    );

    // Optional canonical compat CCS before the encrypted records.
    let mut ccs_or_head = [0u8; 5];
    read_exact_or_timeout(&mut stream, &mut ccs_or_head, "post-SH record head").await;
    let mut first_head = ccs_or_head;
    if ccs_or_head[0] == 0x14 {
        let mut ccs_body = [0u8; 1];
        read_exact_or_timeout(&mut stream, &mut ccs_body, "CCS body").await;
        assert_eq!(ccs_or_head, COMPAT_CCS[..5], "canonical compat CCS header");
        assert_eq!(ccs_body[0], 1, "canonical compat CCS body");
        read_exact_or_timeout(&mut stream, &mut first_head, "first encrypted record head").await;
    }

    // Key schedule input: X25519(controlled private, server ephemeral public).
    let tls_dh = x25519(&CLIENT_X25519_PRIVATE, &server_share);

    // T0 = logical CH (with on-wire ciphertext SID) || patched logical SH.
    let t0 = sha256(&[&logical_ch, &patched_sh]);
    let zero = [0u8; SHA256_LEN];
    let empty_hash = sha256(&[]);
    let early = hkdf_extract(&zero, &zero);
    let derived = derive_secret(&early, b"derived", &empty_hash);
    let handshake_secret = hkdf_extract(&derived, &tls_dh);
    let c_hs = derive_secret(&handshake_secret, b"c hs traffic", &t0);
    let s_hs = derive_secret(&handshake_secret, b"s hs traffic", &t0);
    let master = {
        let derived = derive_secret(&handshake_secret, b"derived", &empty_hash);
        hkdf_extract(&derived, &zero)
    };

    // Read and decrypt the mirrored records until EE || Certificate ||
    // CertificateVerify || server Finished reassemble completely.
    let mut server_hs = RecordKey::from_secret(&s_hs);
    let mut flight_plaintext = Vec::new();
    let mut head = first_head;
    let server_finished_body;
    let t2;
    loop {
        assert_eq!(
            head[0], TLS_RECORD_APPLICATION_DATA,
            "encrypted flight record type"
        );
        assert_eq!(
            &head[1..3],
            &[0x03, 0x03],
            "encrypted flight record version"
        );
        let record_len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        let mut body = vec![0u8; record_len];
        read_exact_or_timeout(&mut stream, &mut body, "encrypted flight record body").await;
        let (inner_type, plaintext) = server_hs.open(&head, &body);
        assert_eq!(inner_type, TLS_RECORD_HANDSHAKE, "server flight inner type");
        flight_plaintext.extend_from_slice(&plaintext);

        // Incremental parse of the four expected handshake messages.
        let mut pos = 0usize;
        let mut kinds = Vec::new();
        let mut complete = true;
        for expected in [8u8, 11, 15, 20] {
            if flight_plaintext.len() < pos + 4 {
                complete = false;
                break;
            }
            let kind = flight_plaintext[pos];
            let msg_len = (usize::from(flight_plaintext[pos + 1]) << 16)
                | (usize::from(flight_plaintext[pos + 2]) << 8)
                | usize::from(flight_plaintext[pos + 3]);
            if kind != expected {
                panic!("server flight message order: expected {expected}, got {kind}");
            }
            if flight_plaintext.len() < pos + 4 + msg_len {
                complete = false;
                break;
            }
            kinds.push((pos, msg_len));
            pos += 4 + msg_len;
        }
        if complete {
            assert_eq!(
                pos,
                flight_plaintext.len(),
                "server Finished ends at the last record's content boundary"
            );
            let (cv_pos, cv_len) = kinds[2];
            let t2_messages = &flight_plaintext[..cv_pos + 4 + cv_len];
            t2 = sha256(&[&logical_ch, &patched_sh, t2_messages]);
            let (fin_pos, fin_len) = kinds[3];
            let fin = &flight_plaintext[fin_pos..fin_pos + 4 + fin_len];
            assert_eq!(fin_len, SHA256_LEN, "SHA-256 Finished body length");
            server_finished_body = fin[4..].to_vec();
            break;
        }
        read_exact_or_timeout(&mut stream, &mut head, "next encrypted record head").await;
    }

    // A real client verifies the server's Finished before answering.  This
    // is the independent client-side check of the whole mirrored flight.
    let s_finished_key = expand_label(&s_hs, b"finished", &[], SHA256_LEN);
    let expected_server_finished = hmac_sha256(&s_finished_key, &[&t2]);
    assert_eq!(
        server_finished_body,
        expected_server_finished.to_vec(),
        "server Finished verify_data under the independently derived key"
    );

    // T3 adds the server Finished; application secrets and the client
    // Finished both snapshot the transcript there.
    let t3 = sha256(&[&logical_ch, &patched_sh, &flight_plaintext]);
    let c_ap = derive_secret(&master, b"c ap traffic", &t3);
    let s_ap = derive_secret(&master, b"s ap traffic", &t3);

    let c_finished_key = expand_label(&c_hs, b"finished", &[], SHA256_LEN);
    let verify_data = hmac_sha256(&c_finished_key, &[&t3]);
    let mut client_finished = Vec::with_capacity(FINISHED_LEN);
    client_finished.push(HS_FINISHED);
    client_finished.extend_from_slice(&[0, 0, SHA256_LEN as u8]);
    client_finished.extend_from_slice(&verify_data);

    ControlledSession {
        stream,
        client_finished,
        client_handshake: RecordKey::from_secret(&c_hs),
        client_application: RecordKey::from_secret(&c_ap),
        server_application: RecordKey::from_secret(&s_ap),
    }
}

// ─── Finished record shaping ──────────────────────────────────────────────

/// Seal the client Finished as fragments with trailing zero padding.  Each
/// `(content, pad)` entry becomes one `17 03 03` record in handshake-seq
/// order; fragmentation across records is wire-legal per spec §7.
fn seal_finished_records(
    key: &mut RecordKey,
    fragments: &[(&[u8], usize)],
    inner_type: u8,
) -> Vec<u8> {
    let mut out = Vec::new();
    for (content, pad) in fragments {
        out.extend_from_slice(&key.seal_with_padding(inner_type, content, *pad));
    }
    out
}

fn positive_fragments(finished: &[u8]) -> [(&[u8], usize); 2] {
    // Split the 36-byte message across two records, both padded.
    [(&finished[..13], 5), (&finished[13..], 29)]
}

fn vless_tcp_request(uuid: &[u8; 16], target: SocketAddr, vision_flow: bool) -> Vec<u8> {
    let mut out = vec![0x00];
    out.extend_from_slice(uuid);
    if vision_flow {
        out.push(18); // addons length
        out.extend_from_slice(&[0x0a, 0x10]);
        out.extend_from_slice(b"xtls-rprx-vision");
    } else {
        out.push(0); // no addons
    }
    out.push(0x01); // command TCP
    out.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        std::net::IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            out.push(0x03);
            out.extend_from_slice(&v6.octets());
        }
    }
    out
}

/// First uplink Vision padding frame: UUID, CONTINUE, content, zero padding.
fn vision_first_frame(uuid: &[u8; 16], content: &[u8], padding_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(uuid);
    out.push(0x00); // COMMAND_PADDING_CONTINUE
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    out
}

// ─── fixtures ─────────────────────────────────────────────────────────────

async fn echo_conn(mut stream: TcpStream) {
    let (mut rd, mut wr) = stream.split();
    let _ = tokio::io::copy(&mut rd, &mut wr).await;
}

async fn start_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(echo_conn(stream));
        }
    });
    addr
}

async fn start_counting_tcp_echo() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            task_accepts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::spawn(echo_conn(stream));
        }
    });
    (addr, accepts)
}

fn ext(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Synthetic target flight: SH echoing the uploaded session id, one compat
/// CCS, and the acceptance record shape — same construction the existing
/// end-to-end hit test uses.
fn mimic_flight(session_id: &[u8; 32]) -> Vec<u8> {
    let share = x25519_public(&[9u8; 32]);
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&[0x03, 0x03]);
    sh_body.extend_from_slice(&[0x66; 32]);
    sh_body.push(32);
    sh_body.extend_from_slice(session_id);
    sh_body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
    sh_body.push(0);
    let versions = ext(0x002b, &0x0304u16.to_be_bytes());
    let mut key_share_body = Vec::new();
    key_share_body.extend_from_slice(&GROUP_X25519.to_be_bytes());
    key_share_body.extend_from_slice(&(share.len() as u16).to_be_bytes());
    key_share_body.extend_from_slice(&share);
    let key_share = ext(EXT_KEY_SHARE, &key_share_body);
    let mut exts = Vec::new();
    exts.extend_from_slice(&versions);
    exts.extend_from_slice(&key_share);
    sh_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    sh_body.extend_from_slice(&exts);
    let mut sh = vec![0x02];
    sh.extend_from_slice(&(sh_body.len() as u32).to_be_bytes()[1..4]);
    sh.extend_from_slice(&sh_body);

    let mut flight = Vec::new();
    flight.extend_from_slice(&[0x16, 0x03, 0x03]);
    flight.extend_from_slice(&(sh.len() as u16).to_be_bytes());
    flight.extend_from_slice(&sh);
    flight.extend_from_slice(&COMPAT_CCS);
    for len in [25u16, 3217, 281, 69] {
        flight.extend_from_slice(&[0x17, 0x03, 0x03]);
        flight.extend_from_slice(&len.to_be_bytes());
        flight.resize(flight.len() + usize::from(len), 0x5a);
    }
    flight
}

async fn read_one_tls_record(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = [0u8; 5];
    stream
        .read_exact(&mut head)
        .await
        .expect("target record head");
    let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .expect("target record body");
    let mut wire = head.to_vec();
    wire.extend_from_slice(&body);
    wire
}

async fn start_mimic_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let first = read_one_tls_record(&mut stream).await;
                assert_eq!(first[0], 0x16, "first uploaded record is a handshake");
                assert_eq!(first[5], 0x01, "first handshake message is ClientHello");
                assert_eq!(first[5 + 38], 32);
                let session_id: [u8; 32] = first[5 + 39..5 + 71].try_into().unwrap();
                let flight = mimic_flight(&session_id);
                stream
                    .write_all(&flight)
                    .await
                    .expect("target flight write");
                stream.flush().await.expect("target flight flush");
                // A REALITY target stays silent after its flight; the mirror
                // side owns closing the socket after the commit settles.
                let mut sink = [0u8; 512];
                loop {
                    match stream.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    addr
}

fn reality_dial_first_spec(dest: SocketAddr) -> VlessListenerSpec {
    VlessListenerSpec {
        users: vec![VlessUserSpec {
            username: "alice".into(),
            uuid: ALICE,
        }],
        security: VlessSecuritySpec::Reality(VlessRealitySpec {
            dest_host: "127.0.0.1".into(),
            dest_port: dest.port(),
            private_key: REALITY_PRIVATE,
            short_ids: vec![SHORT_ID],
            server_names: vec!["localhost".into()],
            max_time_difference_us: 120_000_000,
            limit_fallback_upload: VlessFallbackLimit::default(),
            limit_fallback_download: VlessFallbackLimit::default(),
            mimic: VlessRealityMimicSpec::default(),
        }),
        udp: true,
    }
}

async fn start_listener(
    dest: SocketAddr,
    name: &str,
) -> (u16, Arc<VlessListener>, tokio::task::JoinHandle<()>) {
    let listener = Arc::new(
        VlessListener::new(
            common::direct_tunnel(),
            name.into(),
            reality_dial_first_spec(dest),
        )
        .unwrap(),
    );
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = socket.local_addr().unwrap();
    listener.note_bound_endpoint(&socket, bound);
    let task_listener = Arc::clone(&listener);
    let task = tokio::spawn(async move {
        let _ = task_listener.run_on(socket).await;
    });
    (bound.port(), listener, task)
}

async fn wait_for_metric(
    listener: &VlessListener,
    mut predicate: impl FnMut(&meow_listener::RealityV2MetricsSnapshot) -> bool,
) -> meow_listener::RealityV2MetricsSnapshot {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let snapshot = listener
            .reality_v2_metrics_snapshot()
            .expect("reality metrics");
        if predicate(&snapshot) {
            return snapshot;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "metric condition timed out; last snapshot {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ─── positive-path driver ─────────────────────────────────────────────────

/// Read application records, decrypt with the server application key, and
/// accumulate plaintext into `buf` until at least `needed` bytes are
/// available.
async fn fill_app_plaintext(session: &mut ControlledSession, buf: &mut Vec<u8>, needed: usize) {
    while buf.len() < needed {
        let mut head = [0u8; 5];
        read_exact_or_timeout(&mut session.stream, &mut head, "application record head").await;
        assert_eq!(
            head[0], TLS_RECORD_APPLICATION_DATA,
            "application record type"
        );
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        let mut body = vec![0u8; len];
        read_exact_or_timeout(&mut session.stream, &mut body, "application record body").await;
        let (inner_type, content) = session.server_application.open(&head, &body);
        assert_eq!(
            inner_type, TLS_RECORD_APPLICATION_DATA,
            "app data inner type"
        );
        buf.extend_from_slice(&content);
    }
}

/// The echo response: `00 00` response header, then one padding frame
/// carrying the mirrored echo payload as content.
async fn assert_vision_echo(session: &mut ControlledSession, payload: &[u8]) {
    // `00 00` + uuid(16) + command(1) + content_len(2) + padding_len(2).
    let header_len = 2 + 16 + 1 + 2 + 2;
    let mut plaintext = Vec::new();
    fill_app_plaintext(session, &mut plaintext, header_len).await;
    assert_eq!(&plaintext[..2], &[0x00, 0x00], "VLESS response header");
    assert_eq!(
        &plaintext[2..18],
        &ALICE,
        "first downlink frame carries the user UUID"
    );
    let content_len = usize::from(u16::from_be_bytes([plaintext[19], plaintext[20]]));
    assert_eq!(content_len, payload.len(), "echo content length");
    fill_app_plaintext(session, &mut plaintext, header_len + content_len).await;
    assert_eq!(
        &plaintext[header_len..header_len + content_len],
        payload,
        "echoed Vision content is byte exact"
    );
}

/// Run the positive path with a caller-chosen Finished wire shape: the
/// full Vision echo must complete and exactly one mimic hit is counted.
async fn run_positive(name: &str, with_ccs: bool) {
    let target = start_mimic_target().await;
    let echo = start_tcp_echo().await;
    let (port, listener, task) = start_listener(target, name).await;

    let mut session = controlled_handshake(port).await;
    let finished = session.client_finished.clone();
    let fragments = positive_fragments(&finished);
    let mut one_write = Vec::new();
    if with_ccs {
        one_write.extend_from_slice(&COMPAT_CCS);
    }
    one_write.extend_from_slice(&seal_finished_records(
        &mut session.client_handshake,
        &fragments,
        TLS_RECORD_HANDSHAKE,
    ));

    // The coalesced next application record carries the complete VLESS
    // request and the first Vision padding frame: had the Finished reader
    // consumed even one byte of it, neither could ever parse.
    let payload = b"controlled finished vision echo payload";
    let mut app_plaintext = vless_tcp_request(&ALICE, echo, true);
    app_plaintext.extend_from_slice(&vision_first_frame(&ALICE, payload, 11));
    one_write.extend_from_slice(&session.client_application.seal_with_padding(
        TLS_RECORD_APPLICATION_DATA,
        &app_plaintext,
        0,
    ));

    session
        .stream
        .write_all(&one_write)
        .await
        .expect("single coalesced write");
    session.stream.flush().await.expect("flush coalesced write");

    assert_vision_echo(&mut session, payload).await;

    let snapshot = wait_for_metric(&listener, |s| s.mimic_hit_total == 1).await;
    assert_eq!(snapshot.dial_started_total, 1);
    assert_eq!(snapshot.probe_started_total, 1);
    assert_eq!(snapshot.committed_total, 1);
    assert!(
        snapshot.cover_total.is_empty(),
        "hit path never covers: {:?}",
        snapshot.cover_total
    );
    assert!(
        snapshot.close_total.is_empty(),
        "hit path never closes: {:?}",
        snapshot.close_total
    );
    drop(session.stream);
    task.abort();
}

// ─── negative-path driver ─────────────────────────────────────────────────

/// Write the caller-shaped wire after the real mirrored flight and assert
/// the post-commit close accounting: exactly one
/// `close(wait_finished, finished_invalid)`, no cover, no hit.
async fn run_negative(name: &str, shape: NegativeShape) {
    let target = start_mimic_target().await;
    let (port, listener, task) = start_listener(target, name).await;

    let mut session = controlled_handshake(port).await;
    let wire = shape.build(&mut session);
    session
        .stream
        .write_all(&wire)
        .await
        .expect("write shaped Finished wire");
    session.stream.flush().await.expect("flush shaped wire");

    let snapshot = wait_for_metric(&listener, |s| {
        s.close_total.get(&("wait_finished", "finished_invalid")) == Some(&1)
    })
    .await;
    assert_eq!(
        snapshot.committed_total, 1,
        "commit precedes the Finished stage"
    );
    assert_eq!(snapshot.mimic_hit_total, 0, "rejected Finished never hits");
    assert!(
        snapshot.cover_total.is_empty(),
        "post-commit failures never cover: {:?}",
        snapshot.cover_total
    );
    drop(session.stream);
    task.abort();
}

enum NegativeShape {
    /// Flip one byte of the first Finished record's AEAD tag.
    TagFlip,
    /// Valid AEAD everywhere, but the verify_data carried inside is wrong.
    VerifyDataFlip,
    /// Extra handshake bytes after the Finished inside the same record.
    TrailingHandshakeBytes,
    /// Correct verify_data sealed under a non-handshake inner type.
    WrongInnerType,
    /// Handshake inner type with zero content bytes.
    EmptyHandshakeContent,
    /// Correct Finished fragmented into more than 32 tiny records.
    Over32Records,
    /// Correct Finished in maximally padded records exceeding 65536 wire bytes.
    Over64KWire,
    /// Two canonical compat CCS records before a correct Finished.
    DoubleCcs,
}

impl NegativeShape {
    fn build(self, session: &mut ControlledSession) -> Vec<u8> {
        let finished = session.client_finished.clone();
        match self {
            Self::TagFlip => {
                let fragments = positive_fragments(&finished);
                let mut wire = COMPAT_CCS.to_vec();
                let mut records = seal_finished_records(
                    &mut session.client_handshake,
                    &fragments,
                    TLS_RECORD_HANDSHAKE,
                );
                // The first record ends with its 16-byte tag; flipping its
                // last byte must fail AEAD open before any semantic check.
                let first_len = 5 + (13 + 1 + 5) + 16;
                records[first_len - 1] ^= 0x01;
                wire.extend_from_slice(&records);
                wire
            }
            Self::VerifyDataFlip => {
                let mut bad = finished.clone();
                let last = bad.len() - 1;
                bad[last] ^= 0x01;
                let fragments = positive_fragments(&bad);
                let mut wire = COMPAT_CCS.to_vec();
                wire.extend_from_slice(&seal_finished_records(
                    &mut session.client_handshake,
                    &fragments,
                    TLS_RECORD_HANDSHAKE,
                ));
                wire
            }
            Self::TrailingHandshakeBytes => {
                let mut second = finished[13..].to_vec();
                // A trailing zero byte would vanish into the padding strip;
                // a non-zero byte is reassembled as handshake content.
                second.push(0x14);
                let fragments: [(&[u8], usize); 2] = [(&finished[..13], 5), (&second, 29)];
                let mut wire = COMPAT_CCS.to_vec();
                wire.extend_from_slice(&seal_finished_records(
                    &mut session.client_handshake,
                    &fragments,
                    TLS_RECORD_HANDSHAKE,
                ));
                wire
            }
            Self::WrongInnerType => {
                let fragments = positive_fragments(&finished);
                let mut wire = COMPAT_CCS.to_vec();
                wire.extend_from_slice(&seal_finished_records(
                    &mut session.client_handshake,
                    &fragments,
                    TLS_RECORD_APPLICATION_DATA,
                ));
                wire
            }
            Self::EmptyHandshakeContent => {
                let mut wire = COMPAT_CCS.to_vec();
                wire.extend_from_slice(&session.client_handshake.seal_with_padding(
                    TLS_RECORD_HANDSHAKE,
                    &[],
                    1,
                ));
                wire
            }
            Self::Over32Records => {
                let mut wire = COMPAT_CCS.to_vec();
                // 36 one-byte fragments cannot complete inside the 32-record
                // budget even though every record is a validly sealed piece
                // of the correct Finished — and would complete exactly if
                // the record limit were raised.
                for byte in &finished {
                    wire.extend_from_slice(&session.client_handshake.seal_with_padding(
                        TLS_RECORD_HANDSHAKE,
                        &[*byte],
                        0,
                    ));
                }
                wire
            }
            Self::Over64KWire => {
                let mut wire = COMPAT_CCS.to_vec();
                // Three maximally padded valid records stay below W; the
                // fourth maximum-length header already proves overflow.
                let fragments: [(&[u8], usize); 4] = [
                    (&finished[..9], 16375),
                    (&finished[9..18], 16375),
                    (&finished[18..27], 16375),
                    (&finished[27..], 16375),
                ];
                wire.extend_from_slice(&seal_finished_records(
                    &mut session.client_handshake,
                    &fragments,
                    TLS_RECORD_HANDSHAKE,
                ));
                wire
            }
            Self::DoubleCcs => {
                let fragments = positive_fragments(&finished);
                let mut wire = COMPAT_CCS.to_vec();
                wire.extend_from_slice(&COMPAT_CCS);
                wire.extend_from_slice(&seal_finished_records(
                    &mut session.client_handshake,
                    &fragments,
                    TLS_RECORD_HANDSHAKE,
                ));
                wire
            }
        }
    }
}

// ─── tests (spec §9 T4) ───────────────────────────────────────────────────

/// §9 T4 positive: one write carries the canonical compat CCS, the client
/// Finished fragmented across two records with trailing zero padding, and
/// the coalesced first application record with the first VLESS request
/// bytes.  The Finished reader's exact reads must leave the application
/// record untouched for the `RealityTlsStream` handoff — proven end to end
/// by the Vision echo — and the hit is counted exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_single_write_ccs_fragmented_padded_finished_coalesced_app_record_vision_echo() {
    run_positive("vless-t4-hit-ccs-it", true).await;
}

/// §7 CCS variant: the Finished reader accepts a client that never sends a
/// compat CCS; everything else about the positive path is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_finished_without_compat_ccs_vision_echo() {
    run_positive("vless-t4-hit-noccs-it", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_tampered_finished_record_tag_closes_without_cover_or_hit() {
    run_negative("vless-t4-neg-tag-it", NegativeShape::TagFlip).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_wrong_verify_data_closes_without_cover_or_hit() {
    run_negative("vless-t4-neg-verifydata-it", NegativeShape::VerifyDataFlip).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_handshake_bytes_after_finished_in_same_record_close() {
    run_negative(
        "vless-t4-neg-trailing-it",
        NegativeShape::TrailingHandshakeBytes,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_non_handshake_inner_type_closes() {
    run_negative("vless-t4-neg-innertype-it", NegativeShape::WrongInnerType).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_empty_handshake_content_closes() {
    run_negative(
        "vless-t4-neg-emptycontent-it",
        NegativeShape::EmptyHandshakeContent,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_finished_over_32_records_closes() {
    run_negative("vless-t4-neg-32records-it", NegativeShape::Over32Records).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_finished_over_65536_wire_bytes_closes() {
    run_negative("vless-t4-neg-64kwire-it", NegativeShape::Over64KWire).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_second_compat_ccs_closes() {
    run_negative("vless-t4-neg-doubleccs-it", NegativeShape::DoubleCcs).await;
}

// ─── post-hit VLESS authentication negatives ──────────────────────────────

/// The mimic hit is a TLS-layer event: it is counted when the client
/// Finished verifies, before any VLESS byte is read.  A wrong UUID or a
/// missing vision flow must still hit, must still have run the dial-first
/// fixed-target dial, and must never reach VLESS routing — proven by the
/// counting echo server never accepting a connection.
async fn run_auth_negative(name: &str, uuid: [u8; 16], vision_flow: bool) {
    let target = start_mimic_target().await;
    let (echo, echo_accepts) = start_counting_tcp_echo().await;
    let (port, listener, task) = start_listener(target, name).await;

    let mut session = controlled_handshake(port).await;
    let finished = session.client_finished.clone();
    let fragments = positive_fragments(&finished);
    let mut one_write = COMPAT_CCS.to_vec();
    one_write.extend_from_slice(&seal_finished_records(
        &mut session.client_handshake,
        &fragments,
        TLS_RECORD_HANDSHAKE,
    ));
    let mut app_plaintext = vless_tcp_request(&uuid, echo, vision_flow);
    app_plaintext.extend_from_slice(&vision_first_frame(&uuid, b"unreachable echo payload", 7));
    one_write.extend_from_slice(&session.client_application.seal_with_padding(
        TLS_RECORD_APPLICATION_DATA,
        &app_plaintext,
        0,
    ));
    session
        .stream
        .write_all(&one_write)
        .await
        .expect("write auth-negative wire");
    session
        .stream
        .flush()
        .await
        .expect("flush auth-negative wire");

    let snapshot = wait_for_metric(&listener, |s| s.mimic_hit_total == 1).await;
    assert_eq!(
        snapshot.dial_started_total, 1,
        "the dial-first fixed-target dial is independent of VLESS authentication"
    );
    // Positive synchronization instead of a settling sleep: the server
    // closes the connection once VLESS authentication rejects, so the EOF
    // proves the routing decision has already been made.  Data instead of
    // EOF would mean the request was routed after all.
    let mut buf = [0u8; 64];
    match timeout(T, session.stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("server answered {n} bytes to a rejected VLESS authentication"),
        Err(_) => panic!("server neither routed nor closed a rejected VLESS authentication"),
    }
    assert_eq!(
        echo_accepts.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a rejected VLESS authentication never reaches tunnel routing"
    );
    assert!(
        snapshot.cover_total.is_empty(),
        "post-hit auth failure never covers: {:?}",
        snapshot.cover_total
    );
    drop(session.stream);
    task.abort();
}

/// §9 T4 row: a wrong UUID after a genuine mimic hit produces no VLESS
/// routing dial — distinct from the dial-first target dial, which did run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_hit_with_wrong_uuid_never_reaches_vless_routing() {
    run_auth_negative("vless-t4-wronguuid-it", [0x99; 16], true).await;
}

/// §9 T4 row: a missing vision flow after a genuine mimic hit produces no
/// VLESS routing dial either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_hit_without_vision_flow_never_reaches_vless_routing() {
    run_auth_negative("vless-t4-noflow-it", ALICE, false).await;
}
