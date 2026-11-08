//! QUIC sniffer: the server name from a client's Initial
//! packets, as mihomo's `sniff.QUIC`.
//!
//! Initial packets are encrypted with keys derived from the client's
//! Destination Connection ID alone (RFC 9001 §5.2), so an on-path observer
//! can open them: undo header protection, AES-128-GCM-open the payload,
//! collect its CRYPTO frames and read the SNI out of the ClientHello.
//! Clients spread the ClientHello over several Initials (Chrome's
//! post-quantum key share makes it ~1.8 KB) and shuffle CRYPTO frames, so
//! the frames are reassembled by offset across datagrams.

use boring::aead::{AeadCtx, Algorithm};
use boring::hash::hmac_sha256;
use boring::symm::{encrypt, Cipher};
use smol_str::SmolStr;

const V1: u32 = 1;
const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// Bound on reassembled ClientHello bytes.
const MAX_CRYPTO: usize = 16 * 1024;

/// What one datagram did for the sniff.
#[derive(Debug, PartialEq, Eq)]
pub enum QuicSniffStep {
    /// The server name (the ClientHello is complete and carries one).
    Name(SmolStr),
    /// More Initials are needed.
    More,
    /// Not a QUIC Initial, or a ClientHello without a name: give up.
    Done,
}

/// Reassembles a client's CRYPTO stream across Initial datagrams.
#[derive(Default)]
pub struct QuicSniffer {
    /// `(offset, bytes)` chunks of the Initial CRYPTO stream — disjoint
    /// by construction: a retransmission stores only the ranges it adds.
    chunks: Vec<(usize, Vec<u8>)>,
    /// Bytes of stream `chunks` covers; bounded at `4 * MAX_CRYPTO`.
    total: usize,
}

impl QuicSniffer {
    pub fn feed(&mut self, datagram: &[u8]) -> QuicSniffStep {
        // A datagram may coalesce several long-header packets: walk them
        // all. QUIC packets that are not client Initials (0-RTT, Handshake)
        // are skipped and the sniff goes on, as upstream's does.
        let mut d = datagram;
        let (mut quic, mut opened) = (false, false);
        while !d.is_empty() {
            match open_packet(d) {
                Packet::NotQuic => break,
                Packet::Other(n) => {
                    quic = true;
                    d = &d[n..];
                }
                Packet::Initial(frames, n) => {
                    quic = true;
                    opened = true;
                    if !self.collect(&frames) {
                        return QuicSniffStep::Done;
                    }
                    d = &d[n..];
                }
            }
        }
        if !quic {
            return QuicSniffStep::Done;
        }
        if !opened {
            return QuicSniffStep::More;
        }
        let stream = self.contiguous();
        // ClientHello: type 1, 24-bit length.
        if stream.len() < 4 {
            return QuicSniffStep::More;
        }
        if stream[0] != 1 {
            return QuicSniffStep::Done;
        }
        let len =
            usize::from(stream[1]) << 16 | usize::from(stream[2]) << 8 | usize::from(stream[3]);
        if len + 4 > MAX_CRYPTO {
            return QuicSniffStep::Done;
        }
        if stream.len() < len + 4 {
            return QuicSniffStep::More;
        }
        // sniff_tls reads a TLS record: wrap the handshake message in one.
        let mut record = Vec::with_capacity(len + 9);
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        #[allow(clippy::cast_possible_truncation, reason = "bounded by MAX_CRYPTO")]
        record.extend_from_slice(&((len + 4) as u16).to_be_bytes());
        record.extend_from_slice(&stream[..len + 4]);
        meow_common::sniffer::sniff_tls(&record).map_or(QuicSniffStep::Done, QuicSniffStep::Name)
    }

    /// Add the CRYPTO frames of a decrypted payload; `false` on a frame
    /// that cannot be skipped or a stream over the bound. Frames of every
    /// other type [`skip_frame`] knows are stepped over, so a CRYPTO
    /// frame later in the same packet is still found; a type whose
    /// layout is unknown to us ends the walk keeping what was collected.
    fn collect(&mut self, mut p: &[u8]) -> bool {
        while let Some(&ty) = p.first() {
            match ty {
                0x00 | 0x01 => p = &p[1..], // PADDING, PING
                0x02 | 0x03 => {
                    // ACK: largest, delay, range count, first range, ranges
                    let mut q = &p[1..];
                    let mut fields = [0u64; 4];
                    for f in &mut fields {
                        let Some(v) = varint(&mut q) else {
                            return false;
                        };
                        *f = v;
                    }
                    for _ in 0..fields[2] {
                        if varint(&mut q).is_none() || varint(&mut q).is_none() {
                            return false;
                        }
                    }
                    if ty == 0x03 {
                        for _ in 0..3 {
                            if varint(&mut q).is_none() {
                                return false;
                            }
                        }
                    }
                    p = q;
                }
                0x06 => {
                    let mut q = &p[1..];
                    let (Some(off), Some(len)) = (varint(&mut q), varint(&mut q)) else {
                        return false;
                    };
                    let (Ok(off), Ok(len)) = (usize::try_from(off), usize::try_from(len)) else {
                        return false;
                    };
                    let Some(end) = off.checked_add(len) else {
                        return false;
                    };
                    if len > q.len() || end > MAX_CRYPTO {
                        return false;
                    }
                    // A retransmitted segment must not pay the stream bound
                    // twice: store only the ranges no earlier chunk covers
                    // (keeping `chunks` disjoint and `total` the unique
                    // coverage the guard means to bound), and skip the
                    // frame's bytes whatever their overlap.
                    for (o, l) in self.uncovered(off, len) {
                        self.chunks.push((o, q[o - off..o - off + l].to_vec()));
                        self.total += l;
                    }
                    if self.total > 4 * MAX_CRYPTO {
                        return false;
                    }
                    p = &q[len..];
                }
                _ => match skip_frame(p) {
                    Some(rest) => p = rest,
                    None => return true,
                },
            }
        }
        true
    }

    /// The `(offset, len)` sub-ranges of `[off, off + len)` no stored
    /// chunk covers. Chunks are few — an Initial's CRYPTO frames across
    /// a handful of datagrams — so a sort per arrival is cheap.
    fn uncovered(&self, off: usize, len: usize) -> Vec<(usize, usize)> {
        let mut ranges: Vec<(usize, usize)> =
            self.chunks.iter().map(|(o, d)| (*o, o + d.len())).collect();
        ranges.sort_unstable();
        let mut out = Vec::new();
        let (mut start, end) = (off, off + len);
        for (s, e) in ranges {
            if e <= start {
                continue;
            }
            if s >= end {
                break;
            }
            if s > start {
                out.push((start, s - start));
            }
            start = start.max(e);
        }
        if start < end {
            out.push((start, end - start));
        }
        out
    }

    /// The CRYPTO stream from offset 0 up to the first gap.
    fn contiguous(&mut self) -> Vec<u8> {
        self.chunks.sort_unstable_by_key(|c| c.0);
        let mut out: Vec<u8> = Vec::new();
        for (off, data) in &self.chunks {
            if *off > out.len() {
                break;
            }
            let skip = out.len() - off;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
        }
        out
    }
}

/// QUIC varint decode. The same primitive lives privately in meow-proxy's
/// `hysteria2::proto::read_varint`; deduplicating them would need a
/// cross-crate home, so it is repeated here.
fn varint(p: &mut &[u8]) -> Option<u64> {
    let first = *p.first()?;
    let len = 1usize << (first >> 6);
    if p.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for &b in &p[1..len] {
        v = v << 8 | u64::from(b);
    }
    *p = &p[len..];
    Some(v)
}

/// Advance `p` past `n` varints; `None` on truncation.
fn skip_varints(p: &mut &[u8], n: usize) -> Option<()> {
    for _ in 0..n {
        varint(p)?;
    }
    Some(())
}

/// Advance past a non-CRYPTO frame (`p` starts at its type byte) by the
/// layout RFC 9000 §19 gives it — RFC 9221's for DATAGRAM. `None` when
/// the type is unknown to us (its length cannot be derived) or the frame
/// is truncated.
fn skip_frame(p: &[u8]) -> Option<&[u8]> {
    let ty = *p.first()?;
    let mut q = &p[1..];
    match ty {
        // RESET_STREAM: stream id, error code, final size.
        0x04 => skip_varints(&mut q, 3)?,
        // NEW_TOKEN: token length + token.
        0x07 => {
            let l = usize::try_from(varint(&mut q)?).ok()?;
            q = q.get(l..)?;
        }
        // STREAM: id, offset when 0x04 set, length+data when 0x02 set —
        // without 0x02 the data runs to the packet's end.
        0x08..=0x0f => {
            varint(&mut q)?;
            if ty & 0x04 != 0 {
                varint(&mut q)?;
            }
            if ty & 0x02 != 0 {
                let l = usize::try_from(varint(&mut q)?).ok()?;
                q = q.get(l..)?;
            } else {
                q = &[];
            }
        }
        // MAX_DATA, MAX_STREAMS (bidi/uni), DATA_BLOCKED, STREAMS_BLOCKED
        // (bidi/uni), RETIRE_CONNECTION_ID: a lone varint.
        0x10 | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 | 0x19 => skip_varints(&mut q, 1)?,
        // STOP_SENDING, MAX_STREAM_DATA, STREAM_DATA_BLOCKED: two
        // varints.
        0x05 | 0x11 | 0x15 => skip_varints(&mut q, 2)?,
        // NEW_CONNECTION_ID: sequence, retire-prior-to, a 1-byte cid
        // length + cid, then the 16-byte stateless reset token.
        0x18 => {
            skip_varints(&mut q, 2)?;
            let l = usize::from(*q.first()?);
            q = q.get(1 + l + 16..)?;
        }
        // PATH_CHALLENGE, PATH_RESPONSE: 8 fixed bytes.
        0x1a | 0x1b => q = q.get(8..)?,
        // CONNECTION_CLOSE: error code, offending frame type (0x1c only),
        // reason length + reason.
        0x1c | 0x1d => {
            varint(&mut q)?;
            if ty == 0x1c {
                varint(&mut q)?;
            }
            let l = usize::try_from(varint(&mut q)?).ok()?;
            q = q.get(l..)?;
        }
        // HANDSHAKE_DONE: no fields.
        0x1e => {}
        // DATAGRAM (RFC 9221): length + data when 0x01 set, else the data
        // runs to the packet's end.
        0x30 | 0x31 => {
            if ty == 0x31 {
                let l = usize::try_from(varint(&mut q)?).ok()?;
                q = q.get(l..)?;
            } else {
                q = &[];
            }
        }
        _ => return None,
    }
    Some(q)
}

fn hkdf_expand_label(secret: &[u8], label: &str, len: usize) -> Option<Vec<u8>> {
    let full = ["tls13 ", label].concat();
    let mut info = Vec::with_capacity(4 + full.len());
    #[allow(clippy::cast_possible_truncation, reason = "lengths of 32 or less")]
    {
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(full.len() as u8);
    }
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    info.push(1); // T(1): every output here fits one SHA-256 block
    let t1 = hmac_sha256(secret, &info).ok()?;
    Some(t1[..len].to_vec())
}

/// The first packet of a datagram.
enum Packet {
    /// Not a QUIC v1/v2 long-header packet: nothing more to read.
    NotQuic,
    /// A QUIC packet that is not a readable client Initial, `n` bytes long.
    Other(usize),
    /// A client Initial's plaintext frames, and its length.
    Initial(Vec<u8>, usize),
}

fn open_packet(d: &[u8]) -> Packet {
    let Some(first) = d.first().copied() else {
        return Packet::NotQuic;
    };
    if first & 0xc0 != 0xc0 || d.len() < 7 {
        return Packet::NotQuic; // not a long header
    }
    let Ok(v) = <[u8; 4]>::try_from(&d[1..5]) else {
        return Packet::NotQuic;
    };
    let (salt, prefix, initial_type, retry_type) = match u32::from_be_bytes(v) {
        V1 => (&SALT_V1, "quic", 0, 3),
        V2 => (&SALT_V2, "quicv2", 1, 0),
        _ => return Packet::NotQuic,
    };
    let ty = (first >> 4) & 0x03;
    let is_initial = ty == initial_type;
    match open_long(d, salt, prefix, is_initial, ty != retry_type) {
        Some((Some(frames), n)) => Packet::Initial(frames, n),
        Some((None, n)) => Packet::Other(n),
        None => Packet::NotQuic,
    }
}

/// Walk a long header (`has_length`: Initial, 0-RTT, Handshake — not
/// Retry) and, for an Initial, decrypt it. Returns the plaintext (Initial
/// only) and the packet's length; `None` when the framing is broken.
fn open_long(
    d: &[u8],
    salt: &[u8; 20],
    prefix: &str,
    is_initial: bool,
    has_length: bool,
) -> Option<(Option<Vec<u8>>, usize)> {
    let mut p = &d[5..];
    let dcid_len = usize::from(*p.first()?);
    if dcid_len > 20 || p.len() < 1 + dcid_len {
        return None;
    }
    let dcid = &p[1..=dcid_len];
    p = &p[1 + dcid_len..];
    let scid_len = usize::from(*p.first()?);
    if p.len() < 1 + scid_len {
        return None;
    }
    p = &p[1 + scid_len..];
    if !has_length {
        // A Retry carries no length: the rest of the datagram is its.
        return Some((None, d.len()));
    }
    if is_initial {
        let token_len = usize::try_from(varint(&mut p)?).ok()?;
        if p.len() < token_len {
            return None;
        }
        p = &p[token_len..];
    }
    let length = usize::try_from(varint(&mut p)?).ok()?;
    let pn_offset = d.len() - p.len();
    if p.len() < length {
        return None;
    }
    let end = pn_offset + length;
    if !is_initial {
        return Some((None, end));
    }
    if length < 20 {
        return None;
    }
    Some((
        decrypt_initial(d, dcid, salt, prefix, pn_offset, length),
        end,
    ))
}

fn decrypt_initial(
    d: &[u8],
    dcid: &[u8],
    salt: &[u8; 20],
    prefix: &str,
    pn_offset: usize,
    length: usize,
) -> Option<Vec<u8>> {
    let initial = hmac_sha256(salt, dcid).ok()?;
    let client = hkdf_expand_label(&initial, "client in", 32)?;
    let key = hkdf_expand_label(&client, &[prefix, " key"].concat(), 16)?;
    let iv = hkdf_expand_label(&client, &[prefix, " iv"].concat(), 12)?;
    let hp = hkdf_expand_label(&client, &[prefix, " hp"].concat(), 16)?;

    let sample = &d[pn_offset + 4..pn_offset + 20];
    let mask = encrypt(Cipher::aes_128_ecb(), &hp, None, sample).ok()?;
    let mut header = d[..pn_offset + 4].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(header[0] & 0x03) + 1;
    header.truncate(pn_offset + pn_len);
    let mut pn = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = pn << 8 | u64::from(header[pn_offset + i]);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    for (n, b) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
        *n ^= b;
    }
    let body = &d[pn_offset + pn_len..pn_offset + length];
    if body.len() < 16 {
        return None;
    }
    let (ct, tag) = body.split_at(body.len() - 16);
    let mut plain = ct.to_vec();
    let ctx = AeadCtx::new_default_tag(&Algorithm::aes_128_gcm(), &key).ok()?;
    ctx.open_in_place(&nonce, &mut plain, tag, &header).ok()?;
    Some(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.2: the client Initial's derived keys.
    #[test]
    fn rfc9001_initial_keys() {
        let dcid = hex("8394c8f03e515708");
        let initial = hmac_sha256(&SALT_V1, &dcid).unwrap();
        let client = hkdf_expand_label(&initial, "client in", 32).unwrap();
        assert_eq!(
            client,
            hex("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            hkdf_expand_label(&client, "quic key", 16).unwrap(),
            hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            hkdf_expand_label(&client, "quic iv", 12).unwrap(),
            hex("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            hkdf_expand_label(&client, "quic hp", 16).unwrap(),
            hex("9f50449e04a0e810283a1e9933adedd2")
        );
    }

    #[test]
    fn crypto_frames_reassemble_out_of_order() {
        let mut s = QuicSniffer::default();
        // CRYPTO off 3 "def", then off 0 "abc", with PADDING and PING.
        assert!(s.collect(&[0x06, 0x03, 0x03, b'd', b'e', b'f', 0x00, 0x01]));
        assert!(s.collect(&[0x06, 0x00, 0x03, b'a', b'b', b'c']));
        assert_eq!(s.contiguous(), b"abcdef");
    }

    /// A ClientHello carrying only an SNI for `name`.
    fn client_hello(name: &str) -> Vec<u8> {
        let n = name.len();
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&u16::try_from(n + 5).unwrap().to_be_bytes());
        ext.extend_from_slice(&u16::try_from(n + 3).unwrap().to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
        ext.extend_from_slice(name.as_bytes());
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0];
        hs.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        hs.extend_from_slice(&body);
        hs
    }

    /// Seal `frames` as a v1 client Initial (packet number `pn`, padded to
    /// at least the header-protection sample).
    fn seal_initial(dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
        let initial = hmac_sha256(&SALT_V1, dcid).unwrap();
        let client = hkdf_expand_label(&initial, "client in", 32).unwrap();
        let key = hkdf_expand_label(&client, "quic key", 16).unwrap();
        let iv = hkdf_expand_label(&client, "quic iv", 12).unwrap();
        let hp = hkdf_expand_label(&client, "quic hp", 16).unwrap();
        let mut plain = frames.to_vec();
        plain.resize(plain.len().max(32), 0); // PADDING
        let length = 4 + plain.len() + 16;
        let mut pkt = vec![0xc3, 0, 0, 0, 1, u8::try_from(dcid.len()).unwrap()];
        pkt.extend_from_slice(dcid);
        pkt.extend_from_slice(&[0, 0]); // SCID, token
        pkt.extend_from_slice(&(0x4000 | u16::try_from(length).unwrap()).to_be_bytes());
        let pn_offset = pkt.len();
        pkt.extend_from_slice(&pn.to_be_bytes());
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv);
        for (n, b) in nonce[4..].iter_mut().zip(u64::from(pn).to_be_bytes()) {
            *n ^= b;
        }
        let ctx = AeadCtx::new_default_tag(&Algorithm::aes_128_gcm(), &key).unwrap();
        let mut tag = [0u8; 16];
        ctx.seal_in_place(&nonce, &mut plain, &mut tag, &pkt)
            .unwrap();
        pkt.extend_from_slice(&plain);
        pkt.extend_from_slice(&tag);
        let mask = encrypt(
            Cipher::aes_128_ecb(),
            &hp,
            None,
            &pkt[pn_offset + 4..pn_offset + 20],
        )
        .unwrap();
        pkt[0] ^= mask[0] & 0x0f;
        for i in 0..4 {
            pkt[pn_offset + i] ^= mask[1 + i];
        }
        pkt
    }

    fn crypto(off: usize, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        f.extend_from_slice(&(0x4000 | u16::try_from(off).unwrap()).to_be_bytes());
        f.extend_from_slice(&(0x4000 | u16::try_from(data.len()).unwrap()).to_be_bytes());
        f.extend_from_slice(data);
        f
    }

    /// End to end: a ClientHello split over two Initials — the second
    /// half sent first, coalesced after a 0-RTT-shaped packet — names the
    /// flow; a lone Handshake-type packet keeps the sniff going.
    #[test]
    fn sealed_initials_yield_the_server_name() {
        let dcid = hex("8394c8f03e515708");
        let ch = client_hello("quic.example.org");
        let (a, b) = ch.split_at(ch.len() / 2);
        let mut s = QuicSniffer::default();
        // Handshake packet (type 2), zero-length payload.
        let handshake = [0xe0, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(s.feed(&handshake), QuicSniffStep::More);
        let mut coalesced = vec![0xd0, 0, 0, 0, 1, 0, 0, 0]; // 0-RTT, empty
        coalesced.extend_from_slice(&seal_initial(&dcid, 1, &crypto(a.len(), b)));
        assert_eq!(s.feed(&coalesced), QuicSniffStep::More);
        let first = seal_initial(&dcid, 0, &crypto(0, a));
        assert_eq!(
            s.feed(&first),
            QuicSniffStep::Name("quic.example.org".into())
        );
        // Two Initials in one datagram, each half of the ClientHello.
        let mut both = seal_initial(&dcid, 0, &crypto(0, a));
        both.extend_from_slice(&seal_initial(&dcid, 1, &crypto(a.len(), b)));
        assert_eq!(
            QuicSniffer::default().feed(&both),
            QuicSniffStep::Name("quic.example.org".into())
        );
    }

    #[test]
    fn non_quic_datagrams_are_done() {
        let mut s = QuicSniffer::default();
        assert_eq!(s.feed(b"\x00\x01dns-ish"), QuicSniffStep::Done);
        assert_eq!(s.feed(&[0xc0, 0, 0, 0, 9, 0, 0]), QuicSniffStep::Done);
    }

    /// The stream bound counts unique coverage, not arrivals: CRYPTO
    /// segments retransmitted on a lossy path store only the bytes they
    /// add, so a legitimate flow is never pushed past `4 * MAX_CRYPTO`.
    #[test]
    fn retransmissions_count_only_fresh_bytes() {
        let mut s = QuicSniffer::default();
        assert!(s.collect(&crypto(0, b"abcdefghij")));
        assert_eq!(s.total, 10);
        for _ in 0..5 {
            assert!(s.collect(&crypto(0, b"abcdefghij")));
        }
        assert_eq!(s.total, 10, "a full retransmission adds nothing");
        // [5, 15) overlaps [0, 10): only its five fresh bytes count.
        assert!(s.collect(&crypto(5, b"FGHIJKLMNO")));
        assert_eq!(s.total, 15);
        let mut want = b"abcdefghij".to_vec();
        want.extend_from_slice(b"KLMNO");
        assert_eq!(s.contiguous(), want);
    }

    /// End to end through `feed`: five copies of a 15 KB segment pushed
    /// the pre-fix raw-sum accounting past the bound and aborted the
    /// sniff; unique-coverage accounting still names the flow.
    #[test]
    fn retransmitted_initials_still_yield_the_name() {
        let dcid = hex("8394c8f03e515708");
        let ch = client_hello("retransmit.example.org");
        // Filler beyond the ClientHello's end — repeated five times it
        // would have summed to 75 KB > `4 * MAX_CRYPTO`.
        let pad = vec![0u8; 15000 - ch.len() - 100];
        let filler = crypto(ch.len() + 100, &pad);
        let mut s = QuicSniffer::default();
        for pn in 0..5 {
            assert_eq!(
                s.feed(&seal_initial(&dcid, pn, &filler)),
                QuicSniffStep::More
            );
        }
        assert_eq!(
            s.feed(&seal_initial(&dcid, 5, &crypto(0, &ch))),
            QuicSniffStep::Name("retransmit.example.org".into())
        );
    }

    /// Defined non-CRYPTO frames are stepped over by their RFC 9000 §19
    /// layout, so a CRYPTO frame later in the packet is still read; a
    /// type whose layout cannot be derived ends the walk keeping what
    /// was collected.
    #[test]
    fn defined_frames_are_skipped_not_aborted() {
        // MAX_DATA 0; NEW_CONNECTION_ID (seq 1, retire 0, cid len 2 +
        // cid, 16-byte reset token); PATH_CHALLENGE; then CRYPTO "abc".
        let mut p = vec![0x10, 0x00, 0x18, 0x01, 0x00, 0x02, 0xaa, 0xbb];
        p.extend_from_slice(&[0; 16]);
        p.extend_from_slice(&[0x1a, 0, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&[0x06, 0x00, 0x03, b'a', b'b', b'c']);
        let mut s = QuicSniffer::default();
        assert!(s.collect(&p));
        assert_eq!(s.contiguous(), b"abc");
        // 0x7f's length is not derivable — the walk stops there, but the
        // collected stream stays usable.
        assert!(s.collect(&[0x06, 0x03, 0x03, b'd', b'e', b'f', 0x7f]));
        assert_eq!(s.contiguous(), b"abcdef");
    }
}
