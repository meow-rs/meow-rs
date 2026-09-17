use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use md5::{Digest, Md5};
use rand::RngCore;
use sha2::Sha256;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt};

use meow_common::Metadata;

use super::kdf::{kdf12, kdf16};

/// "c48619fe-8f02-49e0-b9e9-edf763e17e21" — historical v2ray constant
const VMESS_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

const CMD_TCP: u8 = 0x01;
#[allow(dead_code)]
const CMD_UDP: u8 = 0x02;

const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x02;
const ADDR_IPV6: u8 = 0x03;

const OPT_STANDARD: u8 = 0x01;

/// Derive the 16-byte cmd_key from a UUID.
///
/// upstream: transport/vmess/user.go — cmd_key = MD5(UUID || MAGIC)
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(VMESS_MAGIC);
    hasher.finalize().into()
}

/// Security cipher identifier in the VMess header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

impl Security {
    fn to_nibble(self) -> u8 {
        match self {
            Security::Aes128Gcm => 0x03,
            Security::ChaCha20Poly1305 => 0x04,
            Security::None => 0x05,
        }
    }
}

/// Parsed auto cipher: pick AES-GCM on hardware AES, ChaCha20 otherwise.
pub fn auto_security() -> Security {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::arch::is_x86_feature_detected!("aes") {
        return Security::Aes128Gcm;
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Security::Aes128Gcm;
    }
    #[allow(unreachable_code)]
    Security::ChaCha20Poly1305
}

pub struct SealedHeader {
    pub bytes: Vec<u8>,
    pub req_key: [u8; 16],
    pub req_iv: [u8; 16],
    pub resp_v: u8,
}

/// Build and encrypt the full VMess AEAD request header.
///
/// Returns (encrypted_header_bytes, req_key, req_iv, resp_v) for the caller
/// to derive body cipher keys.
fn seal_header(
    cmd_key: &[u8; 16],
    security: Security,
    cmd: HeaderCmd<'_>,
) -> Result<SealedHeader, String> {
    let mut rng = rand::rng();

    // Generate per-connection random values
    let mut req_key = [0u8; 16];
    let mut req_iv = [0u8; 16];
    rng.fill_bytes(&mut req_key);
    rng.fill_bytes(&mut req_iv);
    let resp_v: u8 = (rng.next_u32() & 0xFF) as u8;

    // Connection nonce (8 random bytes) used to derive header key/iv
    let mut conn_nonce = [0u8; 8];
    rng.fill_bytes(&mut conn_nonce);

    // 1) Auth ID (16 bytes, AES-128-ECB encrypted)
    let auth_id = build_auth_id(cmd_key, &mut rng);

    // 2) Build plaintext header
    let plaintext = build_header_plaintext(&req_key, &req_iv, resp_v, security, cmd, &mut rng)?;

    // 3) Derive header encryption keys
    let header_key = kdf16(cmd_key, &[b"VMess Header AEAD Key", &auth_id, &conn_nonce]);
    let header_iv = kdf12(
        cmd_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &conn_nonce],
    );

    // 4) Derive length encryption keys. The salts use an underscore
    //    (`Key_Length` / `Nonce_Length`) in v2ray/xray/mihomo — a space here
    //    mis-derives the key and the server fails to open the header.
    let length_key = kdf16(
        cmd_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce],
    );
    let length_iv = kdf12(
        cmd_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &conn_nonce],
    );

    // 5) Encrypt the header
    let cipher = Aes128Gcm::new_from_slice(&header_key)
        .map_err(|e| format!("vmess: header cipher init: {e}"))?;
    let encrypted_header = cipher
        .encrypt(
            Nonce::from_slice(&header_iv),
            Payload {
                msg: &plaintext,
                aad: &auth_id,
            },
        )
        .map_err(|e| format!("vmess: header encrypt: {e}"))?;

    // 6) Encrypt the length. The length field is the PLAINTEXT header length
    //    (the server reads L then reads L+16 for the tag); using the
    //    ciphertext length here would make the server over-read by 16 bytes.
    let header_len = plaintext.len() as u16;
    let length_cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|e| format!("vmess: length cipher init: {e}"))?;
    let encrypted_length = length_cipher
        .encrypt(
            Nonce::from_slice(&length_iv),
            Payload {
                msg: &header_len.to_be_bytes(),
                aad: &auth_id,
            },
        )
        .map_err(|e| format!("vmess: length encrypt: {e}"))?;

    // 7) Assemble in the exact upstream order:
    //    auth_id(16) || encrypted_length(2+16) || conn_nonce(8) || encrypted_header(N+16)
    //    (v2ray SealVMessAEADHeader). conn_nonce sits AFTER the length block.
    let mut out = Vec::with_capacity(16 + encrypted_length.len() + 8 + encrypted_header.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&encrypted_length);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&encrypted_header);

    Ok(SealedHeader {
        bytes: out,
        req_key,
        req_iv,
        resp_v,
    })
}

/// Seal a VMess request header carrying the given destination and the TCP
/// or UDP command byte.
pub fn seal_request_header(
    cmd_key: &[u8; 16],
    security: Security,
    metadata: &Metadata,
    is_udp: bool,
) -> Result<SealedHeader, String> {
    let cmd = if is_udp {
        HeaderCmd::Udp(metadata)
    } else {
        HeaderCmd::Tcp(metadata)
    };
    seal_header(cmd_key, security, cmd)
}

/// Seal a VMess request header carrying CommandMux (0x03) and no
/// destination — the Mux.Cool-over-VMess session signaling (server:
/// sing-vmess service.go `case CommandMux: return HandleMuxConnection`).
pub fn seal_mux_request_header(
    cmd_key: &[u8; 16],
    security: Security,
) -> Result<SealedHeader, String> {
    seal_header(cmd_key, security, HeaderCmd::Mux)
}

/// Response body key/iv for AEAD VMess, derived from the request body
/// key/iv: `respBodyKey = SHA256(req_key)[..16]`, `respBodyIV = SHA256(req_iv)[..16]`.
///
/// upstream: `transport/vmess/conn.go` (`sendRequest`, AEAD branch)
pub fn response_body_keys(req_key: &[u8; 16], req_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let bk: [u8; 32] = Sha256::digest(req_key).into();
    let bi: [u8; 32] = Sha256::digest(req_iv).into();
    let mut resp_key = [0u8; 16];
    let mut resp_iv = [0u8; 16];
    resp_key.copy_from_slice(&bk[..16]);
    resp_iv.copy_from_slice(&bi[..16]);
    (resp_key, resp_iv)
}

/// Read and validate the AEAD-sealed VMess response header from `rd`, leaving
/// the reader positioned at the first response body record.
///
/// Wire layout (all AES-128-GCM, single-shot): `encrypted_length(2+16)` sealed
/// with (`AEAD Resp Header Len Key`/`IV`), then `encrypted_header(L+16)` sealed
/// with (`AEAD Resp Header Key`/`IV`). The header's first byte must equal the
/// per-connection response-verification byte (`resp_v`).
///
/// upstream: `transport/vmess/conn.go` (`recvResponse`)
pub async fn read_aead_response_header<R: AsyncRead + Unpin>(
    rd: &mut R,
    resp_body_key: &[u8; 16],
    resp_body_iv: &[u8; 16],
    resp_v: u8,
) -> std::io::Result<()> {
    let invalid = |msg: &'static str| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);

    // Length block.
    let len_key = kdf16(resp_body_key, &[b"AEAD Resp Header Len Key"]);
    let len_iv = kdf12(resp_body_iv, &[b"AEAD Resp Header Len IV"]);
    let mut len_ct = [0u8; 18];
    rd.read_exact(&mut len_ct).await?;
    let len_cipher =
        Aes128Gcm::new_from_slice(&len_key).map_err(|_| invalid("vmess: resp len cipher init"))?;
    let len_pt = len_cipher
        .decrypt(Nonce::from_slice(&len_iv), len_ct.as_ref())
        .map_err(|_| invalid("vmess: response length AEAD open failed"))?;
    if len_pt.len() != 2 {
        return Err(invalid("vmess: response length not 2 bytes"));
    }
    let hdr_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;

    // Header block (L plaintext + 16 tag).
    let hdr_key = kdf16(resp_body_key, &[b"AEAD Resp Header Key"]);
    let hdr_iv = kdf12(resp_body_iv, &[b"AEAD Resp Header IV"]);
    let mut hdr_ct = vec![0u8; hdr_len + 16];
    rd.read_exact(&mut hdr_ct).await?;
    let hdr_cipher =
        Aes128Gcm::new_from_slice(&hdr_key).map_err(|_| invalid("vmess: resp hdr cipher init"))?;
    let hdr = hdr_cipher
        .decrypt(Nonce::from_slice(&hdr_iv), hdr_ct.as_ref())
        .map_err(|_| invalid("vmess: response header AEAD open failed"))?;
    if hdr.first() != Some(&resp_v) {
        return Err(invalid("vmess: response header verification byte mismatch"));
    }
    Ok(())
}

fn build_auth_id(cmd_key: &[u8; 16], rng: &mut impl RngCore) -> [u8; 16] {
    let auth_id_key = kdf16(cmd_key, &[b"AES Auth ID Encryption"]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&now.to_be_bytes());
    rng.fill_bytes(&mut block[8..12]);
    let crc = crc32fast::hash(&block[..12]);
    block[12..16].copy_from_slice(&crc.to_be_bytes());

    let aes = Aes128::new_from_slice(&auth_id_key).expect("AES-128 key is 16 bytes");
    aes.encrypt_block(aes::Block::from_mut_slice(&mut block));

    block
}

/// Request command byte (xray `RequestCommand*`).  Mux.Cool-over-VMess
/// signals the session with CommandMux (0x03) and no destination — the
/// server (sing-vmess `service.go`, present since 2022) routes it straight
/// into `HandleMuxConnection`.
const CMD_MUX: u8 = 0x03;

/// The header destination: `None` for CommandMux (no port/address follows
/// the command byte — mirrors sing-vmess `if command != CommandMux`).
#[derive(Clone, Copy)]
enum HeaderCmd<'a> {
    Tcp(&'a Metadata),
    Udp(&'a Metadata),
    Mux,
}

fn build_header_plaintext(
    req_key: &[u8; 16],
    req_iv: &[u8; 16],
    resp_v: u8,
    security: Security,
    cmd: HeaderCmd<'_>,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, String> {
    let padding_len = (rng.next_u32() % 16) as u8;
    let (cmd_byte, metadata) = match cmd {
        HeaderCmd::Tcp(m) => (CMD_TCP, Some(m)),
        HeaderCmd::Udp(m) => (CMD_UDP, Some(m)),
        HeaderCmd::Mux => (CMD_MUX, None),
    };

    let mut buf = Vec::with_capacity(64);
    buf.push(0x01); // version
    buf.extend_from_slice(req_iv);
    buf.extend_from_slice(req_key);
    buf.push(resp_v);
    buf.push(OPT_STANDARD); // opts: S=1
    buf.push((padding_len << 4) | security.to_nibble()); // p(4) || sec(4)
    buf.push(0x00); // reserved
    buf.push(cmd_byte);

    if let Some(metadata) = metadata {
        // Port (big-endian, BEFORE addr_type)
        buf.extend_from_slice(&metadata.dst_port.to_be_bytes());

        // Address encoding
        encode_address(&mut buf, metadata)?;
    }

    // Padding
    if padding_len > 0 {
        let mut pad = [0u8; 15];
        rng.fill_bytes(&mut pad[..padding_len as usize]);
        buf.extend_from_slice(&pad[..padding_len as usize]);
    }

    // FNV-1a hash of everything so far
    let hash = fnv1a32(&buf);
    buf.extend_from_slice(&hash.to_be_bytes());

    Ok(buf)
}

fn encode_address(buf: &mut Vec<u8>, metadata: &Metadata) -> Result<(), String> {
    if !metadata.host.is_empty() {
        let host = metadata.host.as_bytes();
        if host.len() > 255 {
            return Err(format!(
                "vmess: domain too long ({} bytes, max 255)",
                host.len()
            ));
        }
        buf.push(ADDR_DOMAIN);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host);
    } else if let Some(ip) = metadata.dst_ip {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(ADDR_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(ADDR_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        return Err("vmess: no destination address".into());
    }
    Ok(())
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn protocol_constants_and_hashes_match_reference() {
        let uuid: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        assert_eq!(cmd_key(&uuid), cmd_key(&uuid));
        assert_ne!(cmd_key(&uuid), [0u8; 16]);
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c_292c);
        assert_eq!(Security::Aes128Gcm.to_nibble(), 0x03);
        assert_eq!(Security::ChaCha20Poly1305.to_nibble(), 0x04);
        assert_eq!(Security::None.to_nibble(), 0x05);
        assert!(matches!(
            auto_security(),
            Security::Aes128Gcm | Security::ChaCha20Poly1305
        ));
    }

    fn address_encoding_covers_all_wire_variants_and_boundaries() {
        fn encoded(meta: &Metadata) -> Vec<u8> {
            let mut buf = Vec::new();
            encode_address(&mut buf, meta).unwrap();
            buf
        }

        assert_eq!(
            encoded(&Metadata {
                dst_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
                ..Default::default()
            }),
            vec![ADDR_IPV4, 127, 0, 0, 1]
        );

        let ipv6 = encoded(&Metadata {
            dst_ip: Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            ..Default::default()
        });
        assert_eq!(ipv6[0], ADDR_IPV6);
        assert_eq!(ipv6.len(), 17);

        let domain = encoded(&Metadata {
            host: "example.com".into(),
            dst_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            ..Default::default()
        });
        assert_eq!(&domain, b"\x02\x0bexample.com");

        let idn = encoded(&Metadata {
            host: "例え.jp".into(),
            ..Default::default()
        });
        assert_eq!(&idn[2..], "例え.jp".as_bytes());

        let max_domain = encoded(&Metadata {
            host: "a".repeat(255).into(),
            ..Default::default()
        });
        assert_eq!(max_domain[1], 255);
        assert_eq!(max_domain.len(), 257);
    }

    fn address_encoding_rejects_missing_or_oversized_destination() {
        let mut buf = Vec::new();
        assert!(encode_address(&mut buf, &Metadata::default()).is_err());
        assert!(encode_address(
            &mut buf,
            &Metadata {
                host: "a".repeat(256).into(),
                ..Default::default()
            }
        )
        .is_err());
    }

    /// Independently open a sealed request header the way a conformant server
    /// (v2ray `OpenVMessAEADHeader`) does, re-deriving every key from the wire
    /// bytes. This catches the seal-order, plaintext-length, and length-salt
    /// bugs that a self-consistent seal/open pair would hide.
    pub(crate) fn server_open_request_header(
        cmd_key: &[u8; 16],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::{Aead, Payload};
        let auth_id = &wire[0..16];
        let encrypted_length = &wire[16..34]; // 2 + 16 tag
        let conn_nonce = &wire[34..42]; // 8 bytes AFTER the length block
        let encrypted_payload = &wire[42..];

        let length_key = kdf16(
            cmd_key,
            &[b"VMess Header AEAD Key_Length", auth_id, conn_nonce],
        );
        let length_iv = kdf12(
            cmd_key,
            &[b"VMess Header AEAD Nonce_Length", auth_id, conn_nonce],
        );
        let len_cipher = Aes128Gcm::new_from_slice(&length_key).map_err(|e| e.to_string())?;
        let len_pt = len_cipher
            .decrypt(
                Nonce::from_slice(&length_iv),
                Payload {
                    msg: encrypted_length,
                    aad: auth_id,
                },
            )
            .map_err(|_| "length AEAD open failed".to_string())?;
        let l = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        if encrypted_payload.len() != l + 16 {
            return Err(format!(
                "payload len {} != L+16 ({})",
                encrypted_payload.len(),
                l + 16
            ));
        }

        let header_key = kdf16(cmd_key, &[b"VMess Header AEAD Key", auth_id, conn_nonce]);
        let header_iv = kdf12(cmd_key, &[b"VMess Header AEAD Nonce", auth_id, conn_nonce]);
        let hdr_cipher = Aes128Gcm::new_from_slice(&header_key).map_err(|e| e.to_string())?;
        let plaintext = hdr_cipher
            .decrypt(
                Nonce::from_slice(&header_iv),
                Payload {
                    msg: encrypted_payload,
                    aad: auth_id,
                },
            )
            .map_err(|_| "payload AEAD open failed".to_string())?;
        if plaintext.len() != l {
            return Err(format!("plaintext len {} != L {}", plaintext.len(), l));
        }
        Ok(plaintext)
    }

    fn sealed_headers_are_unique_and_server_openable() {
        let uuid: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let ck = cmd_key(&uuid);
        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let sealed = seal_request_header(&ck, Security::Aes128Gcm, &meta, false).unwrap();
        let second = seal_request_header(&ck, Security::Aes128Gcm, &meta, false).unwrap();
        assert_ne!(sealed.bytes, second.bytes);
        assert_ne!(sealed.req_key, second.req_key);
        assert!(sealed.bytes.len() >= 16 + 18 + 8 + 16);
        assert_ne!(sealed.req_key, [0; 16]);
        assert_ne!(sealed.req_iv, [0; 16]);

        let pt = server_open_request_header(&ck, &sealed.bytes)
            .expect("a conformant server must be able to open the sealed header");

        // Plaintext layout: version(1) | req_iv(16) | req_key(16) | resp_v(1) | ...
        assert_eq!(pt[0], 0x01, "version byte");
        assert_eq!(
            &pt[1..17],
            &sealed.req_iv,
            "req_iv round-trips through wire"
        );
        assert_eq!(
            &pt[17..33],
            &sealed.req_key,
            "req_key round-trips through wire"
        );
        assert_eq!(pt[33], sealed.resp_v, "resp_v round-trips through wire");

        // FNV-1a trailer must cover everything before it.
        let body = &pt[..pt.len() - 4];
        let want = fnv1a32(body);
        let got = u32::from_be_bytes([
            pt[pt.len() - 4],
            pt[pt.len() - 3],
            pt[pt.len() - 2],
            pt[pt.len() - 1],
        ]);
        assert_eq!(got, want, "server-visible FNV-1a must validate");
    }

    async fn response_header_round_trips() {
        use aes_gcm::aead::Aead;
        let req_key = [0x11u8; 16];
        let req_iv = [0x22u8; 16];
        let resp_v = 0x5A;
        let (rk, ri) = response_body_keys(&req_key, &req_iv);

        // Server seals a minimal 4-byte response header [resp_v, opt=0, cmdlen=0, 0].
        let hdr_pt = [resp_v, 0x00, 0x00, 0x00];
        let len_key = kdf16(&rk, &[b"AEAD Resp Header Len Key"]);
        let len_iv = kdf12(&ri, &[b"AEAD Resp Header Len IV"]);
        let len_ct = Aes128Gcm::new_from_slice(&len_key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&len_iv),
                (hdr_pt.len() as u16).to_be_bytes().as_ref(),
            )
            .unwrap();
        let hdr_key = kdf16(&rk, &[b"AEAD Resp Header Key"]);
        let hdr_iv = kdf12(&ri, &[b"AEAD Resp Header IV"]);
        let hdr_ct = Aes128Gcm::new_from_slice(&hdr_key)
            .unwrap()
            .encrypt(Nonce::from_slice(&hdr_iv), hdr_pt.as_ref())
            .unwrap();

        let mut wire = Vec::new();
        wire.extend_from_slice(&len_ct);
        wire.extend_from_slice(&hdr_ct);
        wire.extend_from_slice(b"body-records-follow");

        let mut cursor = std::io::Cursor::new(wire);
        read_aead_response_header(&mut cursor, &rk, &ri, resp_v)
            .await
            .expect("client must open the server's response header");

        // Reader is positioned exactly at the body bytes.
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"body-records-follow");

        // A wrong resp_v must be rejected.
        let mut cursor2 = std::io::Cursor::new({
            let mut w = Vec::new();
            w.extend_from_slice(&len_ct);
            w.extend_from_slice(&hdr_ct);
            w
        });
        assert!(
            read_aead_response_header(&mut cursor2, &rk, &ri, resp_v ^ 0xFF)
                .await
                .is_err()
        );
    }

    fn plaintext_layout_and_checksum_match_protocol() {
        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let mut rng = FakeRng(0);
        let req_key = [0u8; 16];
        let req_iv = [0u8; 16];
        let pt = build_header_plaintext(
            &req_key,
            &req_iv,
            0x42,
            Security::Aes128Gcm,
            HeaderCmd::Tcp(&meta),
            &mut rng,
        )
        .unwrap();
        // version(1) + req_iv(16) + req_key(16) + resp_v(1) + opts(1) + p_sec(1) + reserved(1) + cmd(1) = 38
        // Then port(2) then addr_type(1)
        let port_offset = 38;
        let port = u16::from_be_bytes([pt[port_offset], pt[port_offset + 1]]);
        assert_eq!(port, 443, "port must be at offset 38 (before addr_type)");
        assert_eq!(
            pt[port_offset + 2],
            ADDR_DOMAIN,
            "addr_type must follow port"
        );

        let body = &pt[..pt.len() - 4];
        let expected_hash = fnv1a32(body);
        let actual_hash = u32::from_be_bytes([
            pt[pt.len() - 4],
            pt[pt.len() - 3],
            pt[pt.len() - 2],
            pt[pt.len() - 1],
        ]);
        assert_eq!(
            actual_hash, expected_hash,
            "FNV-1a must cover all preceding bytes"
        );
    }

    #[tokio::test]
    async fn header_wire_format_matches_protocol() {
        protocol_constants_and_hashes_match_reference();
        address_encoding_covers_all_wire_variants_and_boundaries();
        address_encoding_rejects_missing_or_oversized_destination();
        plaintext_layout_and_checksum_match_protocol();
        sealed_headers_are_unique_and_server_openable();
        response_header_round_trips().await;
    }

    struct FakeRng(u64);
    impl rand::RngCore for FakeRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_add(1);
            self.0 as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(1);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                *b = self.next_u32() as u8;
            }
        }
    }
}
