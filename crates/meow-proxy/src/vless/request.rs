//! Bounded incremental VLESS request decoder for Vision server inbounds.
//!
//! The decoder never reads speculatively: callers can ask how many bytes the
//! current field still needs and never have to push bytes back into the TLS
//! stream.  All variable fields are bounded by the wire format itself — the
//! largest TCP request is 533 bytes and the largest Mux request 274 bytes.

use std::fmt;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::header::VlessAddr;

pub const VLESS_TCP_REQUEST_MAX_LEN: usize = 533;
pub const VLESS_MUX_REQUEST_MAX_LEN: usize = 274;
pub const XTLS_RPRX_VISION_FLOW: &str = "xtls-rprx-vision";

const VERSION_VLESS: u8 = 0x00;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
const COMMAND_MUX: u8 = 0x03;
const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x02;
const ADDR_IPV6: u8 = 0x03;
const VISION_ADDON_LEN: usize = 18;
const VISION_ADDON_PREFIX: [u8; 2] = [0x0a, 0x10];

/// xray's wire-flow rule: configured flow strings are truncated to the
/// first 16 bytes before comparison/encoding.  In particular the client-local
/// `xtls-rprx-vision-udp443` suffix never appears on the wire.
pub fn flow_wire_bytes(flow: &str) -> &[u8] {
    let bytes = flow.as_bytes();
    &bytes[..bytes.len().min(16)]
}

pub fn flow_is_wire_vision(flow: &str) -> bool {
    flow_wire_bytes(flow) == XTLS_RPRX_VISION_FLOW.as_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub uuid: [u8; 16],
    pub command: VlessRequestCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessRequestCommand {
    Tcp { port: u16, target: VlessAddr },
    Mux,
}

#[derive(Debug)]
pub enum VlessRequestError {
    Io(io::Error),
    UnexpectedEof,
    InvalidVersion(u8),
    MissingVisionFlow,
    InvalidVisionFlow,
    UnsupportedUdp,
    UnknownCommand(u8),
    InvalidAddressType(u8),
    PortZero,
    EmptyDomain,
    InvalidDomain,
}

impl fmt::Display for VlessRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "vless request io: {error}"),
            Self::UnexpectedEof => write!(f, "vless request truncated"),
            Self::InvalidVersion(version) => {
                write!(f, "vless request version {version:#04x} is not 0x00")
            }
            Self::MissingVisionFlow => write!(f, "vless request does not declare a flow"),
            Self::InvalidVisionFlow => {
                write!(f, "vless request flow is not exactly xtls-rprx-vision")
            }
            Self::UnsupportedUdp => {
                write!(f, "xtls-rprx-vision does not accept bare VLESS UDP")
            }
            Self::UnknownCommand(command) => {
                write!(f, "vless request command {command:#04x} is unknown")
            }
            Self::InvalidAddressType(atype) => {
                write!(f, "vless request address type {atype:#04x} is unknown")
            }
            Self::PortZero => write!(f, "vless TCP destination port 0 is invalid"),
            Self::EmptyDomain => write!(f, "vless TCP destination domain is empty"),
            Self::InvalidDomain => write!(f, "vless TCP destination is not a valid hostname"),
        }
    }
}

impl std::error::Error for VlessRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for VlessRequestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeStep {
    Version,
    Uuid,
    AddonsLen,
    Addons,
    Command,
    Port,
    AddrType,
    DomainLen,
    Domain,
    Ipv4,
    Ipv6,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlessRequestFeed {
    pub consumed: usize,
    pub request_complete: bool,
}

/// Incremental, allocation-free decoder state.  `feed` may receive bytes
/// spanning several fields; it consumes exactly the request bytes and stops
/// at the first byte of the following Vision frame.
pub struct VlessRequestDecoder {
    step: DecodeStep,
    pos: usize,
    total_len: usize,
    uuid: [u8; 16],
    addons_len: usize,
    addons: [u8; VISION_ADDON_LEN],
    port_bytes: [u8; 2],
    command: u8,
    addr_type: u8,
    domain_len: usize,
    domain: [u8; 255],
    ipv4: [u8; 4],
    ipv6: [u8; 16],
}

impl Default for VlessRequestDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl VlessRequestDecoder {
    pub fn new() -> Self {
        Self {
            step: DecodeStep::Version,
            pos: 0,
            total_len: 0,
            uuid: [0; 16],
            addons_len: 0,
            addons: [0; VISION_ADDON_LEN],
            port_bytes: [0; 2],
            command: 0,
            addr_type: 0,
            domain_len: 0,
            domain: [0; 255],
            ipv4: [0; 4],
            ipv6: [0; 16],
        }
    }

    /// Bytes still needed to finish the current field.  An async reader can
    /// cap every read at this value and therefore never consume the first
    /// Vision frame by accident.
    pub fn needed_in_current_field(&self) -> usize {
        match self.step {
            DecodeStep::Version
            | DecodeStep::AddonsLen
            | DecodeStep::Command
            | DecodeStep::AddrType
            | DecodeStep::DomainLen => 1 - self.pos,
            DecodeStep::Uuid => self.uuid.len() - self.pos,
            DecodeStep::Addons => self.addons_len - self.pos,
            DecodeStep::Port => self.port_bytes.len() - self.pos,
            DecodeStep::Domain => self.domain_len - self.pos,
            DecodeStep::Ipv4 => self.ipv4.len() - self.pos,
            DecodeStep::Ipv6 => self.ipv6.len() - self.pos,
            DecodeStep::Done => 0,
        }
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    fn advance_step(&mut self, step: DecodeStep) {
        self.step = step;
        self.pos = 0;
    }

    fn finish_addons(&mut self) -> Result<(), VlessRequestError> {
        if self.addons[..VISION_ADDON_PREFIX.len()] != VISION_ADDON_PREFIX
            || &self.addons[VISION_ADDON_PREFIX.len()..] != XTLS_RPRX_VISION_FLOW.as_bytes()
        {
            return Err(VlessRequestError::InvalidVisionFlow);
        }
        self.advance_step(DecodeStep::Command);
        Ok(())
    }

    fn finish_command(&mut self, command: u8) -> Result<(), VlessRequestError> {
        self.command = command;
        match command {
            COMMAND_TCP => {
                self.advance_step(DecodeStep::Port);
                Ok(())
            }
            COMMAND_UDP => Err(VlessRequestError::UnsupportedUdp),
            COMMAND_MUX => {
                // xray writes no port/address bytes for a Mux command; the
                // request ends here and the XUDP frames arrive inside the
                // Vision content stream.
                self.advance_step(DecodeStep::Done);
                Ok(())
            }
            other => Err(VlessRequestError::UnknownCommand(other)),
        }
    }

    fn finish_port(&mut self) -> Result<(), VlessRequestError> {
        if self.port() == 0 {
            return Err(VlessRequestError::PortZero);
        }
        self.advance_step(DecodeStep::AddrType);
        Ok(())
    }

    fn port(&self) -> u16 {
        u16::from_be_bytes(self.port_bytes)
    }

    fn finish_addr_type(&mut self, atype: u8) -> Result<(), VlessRequestError> {
        self.addr_type = atype;
        match atype {
            ADDR_IPV4 => {
                self.advance_step(DecodeStep::Ipv4);
                Ok(())
            }
            ADDR_DOMAIN => {
                self.advance_step(DecodeStep::DomainLen);
                Ok(())
            }
            ADDR_IPV6 => {
                self.advance_step(DecodeStep::Ipv6);
                Ok(())
            }
            other => Err(VlessRequestError::InvalidAddressType(other)),
        }
    }

    fn finish_domain(&mut self) -> Result<(), VlessRequestError> {
        let bytes = &self.domain[..self.domain_len];
        let Ok(domain) = std::str::from_utf8(bytes) else {
            return Err(VlessRequestError::InvalidDomain);
        };
        if !meow_common::is_valid_host(domain) {
            return Err(VlessRequestError::InvalidDomain);
        }
        self.advance_step(DecodeStep::Done);
        Ok(())
    }

    fn target(&self) -> VlessAddr {
        match self.addr_type {
            ADDR_IPV4 => VlessAddr::Ipv4(self.ipv4),
            ADDR_IPV6 => VlessAddr::Ipv6(self.ipv6),
            ADDR_DOMAIN => {
                let domain = std::str::from_utf8(&self.domain[..self.domain_len])
                    .expect("domain UTF-8 is validated before Done");
                VlessAddr::domain(domain).expect("wire domain length is at most 255")
            }
            _ => unreachable!("target requested before a valid address type"),
        }
    }

    pub fn request(&self) -> Option<VlessRequest> {
        if self.step != DecodeStep::Done {
            return None;
        }
        let command = match self.command {
            COMMAND_MUX => VlessRequestCommand::Mux,
            COMMAND_TCP => VlessRequestCommand::Tcp {
                port: self.port(),
                target: self.target(),
            },
            _ => unreachable!("unknown commands fail at decode time"),
        };
        Some(VlessRequest {
            uuid: self.uuid,
            command,
        })
    }

    /// Feed bytes into the decoder.  The return value is the number of input
    /// bytes consumed; once complete, trailing bytes belong to the Vision
    /// stream and are deliberately left untouched.
    pub fn feed(&mut self, input: &[u8]) -> Result<VlessRequestFeed, VlessRequestError> {
        let mut consumed = 0usize;
        while consumed < input.len() && self.step != DecodeStep::Done {
            let byte = input[consumed];
            consumed += 1;
            self.total_len += 1;
            debug_assert!(self.total_len <= VLESS_TCP_REQUEST_MAX_LEN);

            match self.step {
                DecodeStep::Version => {
                    if byte != VERSION_VLESS {
                        return Err(VlessRequestError::InvalidVersion(byte));
                    }
                    self.advance_step(DecodeStep::Uuid);
                }
                DecodeStep::Uuid => {
                    self.uuid[self.pos] = byte;
                    self.pos += 1;
                    if self.pos == self.uuid.len() {
                        self.advance_step(DecodeStep::AddonsLen);
                    }
                }
                DecodeStep::AddonsLen => {
                    if byte == 0 {
                        return Err(VlessRequestError::MissingVisionFlow);
                    }
                    self.addons_len = byte as usize;
                    if self.addons_len != VISION_ADDON_LEN {
                        // Unknown, duplicate or additional addon fields are
                        // all fatal for the Vision-only first version.  Failing
                        // at the length byte is safe because this conn is
                        // closed either way and avoids attacker-controlled work.
                        return Err(VlessRequestError::InvalidVisionFlow);
                    }
                    self.advance_step(DecodeStep::Addons);
                }
                DecodeStep::Addons => {
                    self.addons[self.pos] = byte;
                    self.pos += 1;
                    if self.pos == self.addons_len {
                        self.finish_addons()?;
                    }
                }
                DecodeStep::Command => self.finish_command(byte)?,
                DecodeStep::Port => {
                    self.port_bytes[self.pos] = byte;
                    self.pos += 1;
                    if self.pos == self.port_bytes.len() {
                        self.finish_port()?;
                    }
                }
                DecodeStep::AddrType => self.finish_addr_type(byte)?,
                DecodeStep::DomainLen => {
                    if byte == 0 {
                        return Err(VlessRequestError::EmptyDomain);
                    }
                    self.domain_len = byte as usize;
                    self.advance_step(DecodeStep::Domain);
                }
                DecodeStep::Domain => {
                    self.domain[self.pos] = byte;
                    self.pos += 1;
                    if self.pos == self.domain_len {
                        self.finish_domain()?;
                    }
                }
                DecodeStep::Ipv4 => {
                    self.ipv4[self.pos] = byte;
                    self.pos += 1;
                    if self.pos == self.ipv4.len() {
                        self.advance_step(DecodeStep::Done);
                    }
                }
                DecodeStep::Ipv6 => {
                    self.ipv6[self.pos] = byte;
                    self.pos += 1;
                    if self.pos == self.ipv6.len() {
                        self.advance_step(DecodeStep::Done);
                    }
                }
                DecodeStep::Done => unreachable!("loop guards Done"),
            }
        }
        Ok(VlessRequestFeed {
            consumed,
            request_complete: self.step == DecodeStep::Done,
        })
    }
}

/// Read one Vision VLESS request without ever consuming a byte of the first
/// padding frame.  Reads are capped to the exact field remainder; the fixed
/// scratch is independent of peer-supplied lengths.
pub async fn read_vless_request<R>(reader: &mut R) -> Result<VlessRequest, VlessRequestError>
where
    R: AsyncRead + Unpin,
{
    let mut decoder = VlessRequestDecoder::new();
    let mut scratch = [0u8; 255];
    loop {
        let need = decoder.needed_in_current_field();
        if need == 0 {
            // A zero-length state is terminal for this decoder; valid addon
            // and domain lengths are non-zero by construction.
            return Err(VlessRequestError::UnexpectedEof);
        }
        let n = reader.read(&mut scratch[..need]).await?;
        if n == 0 {
            return Err(VlessRequestError::UnexpectedEof);
        }
        let fed = decoder.feed(&scratch[..n])?;
        debug_assert_eq!(fed.consumed, n);
        if fed.request_complete {
            return decoder.request().ok_or(VlessRequestError::UnexpectedEof);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::golden::vectors;

    const UUID: [u8; 16] = vectors::GOLDEN_UUID;

    fn vision_addons() -> Vec<u8> {
        let mut addons = vec![0x12, 0x0a, 0x10];
        addons.extend_from_slice(XTLS_RPRX_VISION_FLOW.as_bytes());
        addons
    }

    /// Length-prefixed domain bytes for the address slot.
    fn domain_addr(name: &str) -> Vec<u8> {
        let mut addr = vec![name.len() as u8];
        addr.extend_from_slice(name.as_bytes());
        addr
    }

    /// Encode a request the way xray's `EncodeRequestHeader` lays it out.
    fn encode_request(uuid: &[u8; 16], command: u8, target: Option<(u16, u8, &[u8])>) -> Vec<u8> {
        let mut out = vec![0x00];
        out.extend_from_slice(uuid);
        out.extend_from_slice(&vision_addons());
        out.push(command);
        if let Some((port, atype, addr)) = target {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(atype);
            out.extend_from_slice(addr);
        }
        out
    }

    fn decode_one(bytes: &[u8]) -> Result<VlessRequest, VlessRequestError> {
        let mut decoder = VlessRequestDecoder::new();
        let fed = decoder.feed(bytes)?;
        assert!(fed.request_complete, "request must complete in one feed");
        decoder.request().ok_or(VlessRequestError::UnexpectedEof)
    }

    // ─── Golden vectors ─────────────────────────────────────────────────

    #[test]
    fn golden_01_tcp_request_parses_byte_exactly() {
        let bytes = vectors::decode(vectors::TCP_REQUEST_FIRST_UPLINK_FRAME);
        // The request header is exactly the first 52 bytes; the first
        // Vision frame follows immediately.
        let request = decode_one(&bytes[..52]).expect("golden request parses");
        assert_eq!(request.uuid, UUID);
        let VlessRequestCommand::Tcp { port, target } = request.command else {
            panic!("golden command must be TCP");
        };
        assert_eq!(port, 443);
        assert_eq!(target, VlessAddr::domain("example.com").unwrap());

        // Feeding the whole vector — header and first frame together —
        // consumes exactly the 52 request bytes and leaves the frame alone.
        let mut decoder = VlessRequestDecoder::new();
        let fed = decoder.feed(&bytes).unwrap();
        assert!(fed.request_complete);
        assert_eq!(fed.consumed, 52);
        assert_eq!(decoder.total_len(), 52);
    }

    #[test]
    fn golden_02_empty_first_frame_request_is_identical() {
        let bytes = vectors::decode(vectors::TCP_REQUEST_EMPTY_FIRST_FRAME);
        let mut decoder = VlessRequestDecoder::new();
        let fed = decoder.feed(&bytes).unwrap();
        assert!(fed.request_complete);
        assert_eq!(fed.consumed, 52);
        let request = decoder.request().unwrap();
        assert_eq!(request.uuid, UUID);
        assert!(matches!(
            request.command,
            VlessRequestCommand::Tcp { port: 443, .. }
        ));
    }

    #[test]
    fn byte_by_byte_feeding_matches_one_shot() {
        let bytes = vectors::decode(vectors::TCP_REQUEST_FIRST_UPLINK_FRAME);
        let mut decoder = VlessRequestDecoder::new();
        let mut consumed = 0usize;
        for &byte in &bytes[..52] {
            let fed = decoder.feed(&[byte]).unwrap();
            consumed += fed.consumed;
            assert_eq!(fed.consumed, 1);
        }
        assert_eq!(consumed, 52);
        let request = decoder.request().expect("complete after 52 bytes");
        assert_eq!(request.uuid, UUID);
    }

    #[tokio::test]
    async fn read_vless_request_never_touches_the_first_frame() {
        let bytes = vectors::decode(vectors::TCP_REQUEST_FIRST_UPLINK_FRAME);
        // One contiguous stream: request + first vision frame.  The async
        // reader must leave every frame byte unread.
        let mut slice: &[u8] = &bytes;
        let request = read_vless_request(&mut slice).await.unwrap();
        assert_eq!(request.uuid, UUID);
        assert_eq!(slice.len(), bytes.len() - 52, "frame bytes stay unread");
        assert_eq!(&slice[..16], &UUID);
    }

    // ─── Shape coverage ─────────────────────────────────────────────────

    #[test]
    fn mux_request_ends_after_the_command_byte() {
        let bytes = encode_request(&UUID, 0x03, None);
        assert_eq!(bytes.len(), 37);
        let request = decode_one(&bytes).unwrap();
        assert!(matches!(request.command, VlessRequestCommand::Mux));
    }

    #[test]
    fn ipv4_and_ipv6_targets_parse() {
        let v4 = encode_request(&[1; 16], 0x01, Some((8080, 0x01, &[127, 0, 0, 1])));
        let request = decode_one(&v4).unwrap();
        assert_eq!(
            request.command,
            VlessRequestCommand::Tcp {
                port: 8080,
                target: VlessAddr::Ipv4([127, 0, 0, 1])
            }
        );

        let v6 = encode_request(&[1; 16], 0x01, Some((8080, 0x03, &[0x20; 16])));
        let request = decode_one(&v6).unwrap();
        assert_eq!(
            request.command,
            VlessRequestCommand::Tcp {
                port: 8080,
                target: VlessAddr::Ipv6([0x20; 16])
            }
        );
    }

    #[test]
    fn longest_domain_request_stays_within_the_tcp_bound() {
        let domain = vec![b'a'; 255];
        let mut addr = vec![255u8];
        addr.extend_from_slice(&domain);
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x02, &addr)));
        // 1+16+1+18+1+2+1+1+255 = 296 for the exact vision addon; the 533
        // contract bound counts the u8 addon/domain lengths at their max.
        assert!(bytes.len() <= VLESS_TCP_REQUEST_MAX_LEN);
        assert!(bytes.len() <= 296);
        let result = decode_one(&bytes);
        // 255 bytes of 'a' is a single over-long DNS label — rejected as a
        // hostname, which is exactly why the bound is structural, not valid.
        assert!(matches!(result, Err(VlessRequestError::InvalidDomain)));
    }

    #[test]
    fn max_valid_domain_labels_parse() {
        // 63-byte labels, four of them minus separators fit the hostname
        // rules: 63+1+63+1+63+1+61 = 253 chars.
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(name.len(), 253);
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x02, &domain_addr(&name))));
        let request = decode_one(&bytes).unwrap();
        assert_eq!(
            request.command,
            VlessRequestCommand::Tcp {
                port: 443,
                target: VlessAddr::domain(&name).unwrap()
            }
        );
    }

    // ─── Rejections ─────────────────────────────────────────────────────

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = encode_request(&UUID, 0x03, None);
        bytes[0] = 0x01;
        assert!(matches!(
            decode_one(&bytes),
            Err(VlessRequestError::InvalidVersion(0x01))
        ));
    }

    #[test]
    fn rejects_missing_and_malformed_flow_addons() {
        // addons_len = 0: no flow declared.
        let mut bytes = vec![0x00];
        bytes.extend_from_slice(&UUID);
        bytes.push(0x00);
        bytes.push(0x03);
        assert!(matches!(
            decode_one(&bytes),
            Err(VlessRequestError::MissingVisionFlow)
        ));

        // addons_len of a different protobuf shape — unknown/additional
        // fields are fatal for the vision-only inbound.
        for len in [1u8, 17, 19, 0xff] {
            let mut bytes = vec![0x00];
            bytes.extend_from_slice(&UUID);
            bytes.push(len);
            bytes.extend(std::iter::repeat_n(0x0a, len as usize));
            bytes.push(0x03);
            assert!(
                matches!(
                    decode_one(&bytes),
                    Err(VlessRequestError::InvalidVisionFlow)
                ),
                "addons_len {len} must be rejected"
            );
        }

        // Right length, wrong protobuf prefix or flow string.
        for (prefix, flow) in [
            ([0x0a, 0x11], *b"xtls-rprx-vision"),
            ([0x0a, 0x10], *b"xtls-rprx-visioN"),
            ([0x12, 0x10], *b"xtls-rprx-vision"),
        ] {
            let mut bytes = vec![0x00];
            bytes.extend_from_slice(&UUID);
            bytes.push(0x12);
            bytes.extend_from_slice(&prefix);
            bytes.extend_from_slice(&flow);
            bytes.push(0x03);
            assert!(matches!(
                decode_one(&bytes),
                Err(VlessRequestError::InvalidVisionFlow)
            ));
        }
    }

    #[test]
    fn rejects_udp_and_unknown_commands() {
        for (command, expect) in [
            (0x02u8, "udp"),
            (0x00, "unknown"),
            (0x04, "unknown"),
            (0xff, "unknown"),
        ] {
            let bytes = encode_request(&UUID, command, Some((443, 0x01, &[1, 1, 1, 1])));
            let result = decode_one(&bytes);
            match expect {
                "udp" => assert!(
                    matches!(result, Err(VlessRequestError::UnsupportedUdp)),
                    "command {command:#x}: {result:?}"
                ),
                _ => assert!(
                    matches!(result, Err(VlessRequestError::UnknownCommand(_))),
                    "command {command:#x}: {result:?}"
                ),
            }
        }
    }

    #[test]
    fn rejects_port_zero_and_bad_addresses() {
        let bytes = encode_request(&UUID, 0x01, Some((0, 0x01, &[1, 1, 1, 1])));
        assert!(matches!(
            decode_one(&bytes),
            Err(VlessRequestError::PortZero)
        ));

        // Unknown address type.
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x09, &[1, 1, 1, 1])));
        assert!(matches!(
            decode_one(&bytes),
            Err(VlessRequestError::InvalidAddressType(0x09))
        ));

        // Empty domain.
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x02, &[0x00])));
        assert!(matches!(
            decode_one(&bytes),
            Err(VlessRequestError::EmptyDomain)
        ));

        // Invalid UTF-8 in the domain.
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x02, &[3, 0xff, 0xfe, 0xfd])));
        assert!(matches!(
            decode_one(&bytes),
            Err(VlessRequestError::InvalidDomain)
        ));

        // Valid UTF-8 but not a hostname.
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x02, &[4, b'?', b'?', b'?', b'?'])));
        assert!(matches!(
            decode_one(&bytes),
            Err(VlessRequestError::InvalidDomain)
        ));
    }

    #[test]
    fn truncation_at_every_offset_is_cleanly_rejected() {
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x02, &domain_addr("example.com"))));
        let full = decode_one(&bytes).unwrap();
        assert!(matches!(full.command, VlessRequestCommand::Tcp { .. }));
        for cut in 0..bytes.len() {
            let mut decoder = VlessRequestDecoder::new();
            // Early field rejections (wrong version etc.) cannot happen
            // here since the bytes are valid — but any error is also a
            // clean rejection rather than a hang or panic.
            if let Ok(fed) = decoder.feed(&bytes[..cut]) {
                assert!(
                    !fed.request_complete,
                    "cut {cut}: a strict prefix must not complete"
                );
            }
        }
    }

    #[tokio::test]
    async fn read_vless_request_reports_truncation_as_unexpected_eof() {
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x01, &[1, 1, 1, 1])));
        for cut in [0usize, 1, 17, 20, 36, 40] {
            let mut slice: &[u8] = &bytes[..cut];
            let result = read_vless_request(&mut slice).await;
            assert!(
                matches!(result, Err(VlessRequestError::UnexpectedEof)),
                "cut {cut}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn read_vless_request_tolerates_single_byte_delivery() {
        use tokio::io::AsyncWriteExt;
        let bytes = encode_request(&UUID, 0x01, Some((443, 0x02, &domain_addr("example.com"))));
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let feed = bytes.clone();
        let producer = tokio::spawn(async move {
            for &byte in &feed {
                writer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let request = read_vless_request(&mut reader).await.unwrap();
        assert_eq!(request.uuid, UUID);
        producer.await.unwrap();
    }

    #[test]
    fn flow_wire_truncation_matches_xray() {
        assert_eq!(flow_wire_bytes("xtls-rprx-vision"), b"xtls-rprx-vision");
        assert!(flow_is_wire_vision("xtls-rprx-vision"));
        // The client-local udp443 suffix truncates to the same wire flow.
        assert!(flow_is_wire_vision("xtls-rprx-vision-udp443"));
        assert!(!flow_is_wire_vision("xtls-rprx-visio"));
        assert!(!flow_is_wire_vision(""));
        // The wire flow is exactly 16 bytes, so every string with that
        // prefix truncates to it — xray compares the truncated form.
        assert!(flow_is_wire_vision("xtls-rprx-visionX"));
        assert!(!flow_is_wire_vision("Xtls-rprx-vision"));
    }
}
