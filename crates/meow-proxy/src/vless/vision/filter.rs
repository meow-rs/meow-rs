//! Incremental inner-TLS recognition shared by Vision server roles.
//!
//! The scanner follows TLS record boundaries across arbitrary chunking and
//! parses the ServerHello handshake fields instead of looking for a magic
//! byte substring.  All state is fixed-size: long handshake messages are
//! streamed through the parser, never reassembled into an allocation.

use super::codec::{
    TLS13_CIPHER_SUITES, TLS_CLIENT_HELLO, TLS_FILTER_PACKETS, TLS_HANDSHAKE, TLS_MAJOR,
    TLS_SERVER_HELLO,
};

const TLS_VERSION_1_2: u16 = 0x0303;
const TLS_VERSION_1_3: u16 = 0x0304;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const SERVER_HELLO_MIN_LEN: usize = 2 + 32 + 1 + 2 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServerHelloOutcome {
    tls13_supported: bool,
    cipher: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerHelloStage {
    ServerVersion,
    Random,
    SessionIdLen,
    SessionId,
    CipherSuite,
    Compression,
    ExtensionsLen,
    ExtensionHeader,
    ExtensionBody,
    Complete,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserFeed {
    Running,
    Complete,
    Invalid,
}

/// Streaming parser for the body of one ServerHello handshake message.  It
/// validates the exact extensions-vector layout and remembers only the few
/// bytes needed for the cipher and supported_versions decision.
struct ServerHelloParser {
    body_len: usize,
    pos: usize,
    stage: ServerHelloStage,
    scratch: [u8; 4],
    scratch_len: usize,
    skip_remaining: usize,
    server_version: Option<u16>,
    cipher: Option<u16>,
    compression: Option<u8>,
    extensions_remaining: usize,
    ext_type: u16,
    ext_len: usize,
    ext_pos: usize,
    ext_value_prefix: [u8; 4],
    supported_versions_seen: bool,
    supported_versions_tls13: bool,
    supported_versions_duplicate: bool,
}

impl ServerHelloParser {
    fn new(body_len: usize) -> Self {
        Self {
            body_len,
            pos: 0,
            stage: if body_len < SERVER_HELLO_MIN_LEN {
                ServerHelloStage::Invalid
            } else {
                ServerHelloStage::ServerVersion
            },
            scratch: [0; 4],
            scratch_len: 0,
            skip_remaining: 0,
            server_version: None,
            cipher: None,
            compression: None,
            extensions_remaining: 0,
            ext_type: 0,
            ext_len: 0,
            ext_pos: 0,
            ext_value_prefix: [0; 4],
            supported_versions_seen: false,
            supported_versions_tls13: false,
            supported_versions_duplicate: false,
        }
    }

    fn fail(&mut self) -> ParserFeed {
        self.stage = ServerHelloStage::Invalid;
        ParserFeed::Invalid
    }

    fn complete(&mut self) -> ParserFeed {
        self.stage = ServerHelloStage::Complete;
        ParserFeed::Complete
    }

    fn push_scratch(&mut self, byte: u8) {
        self.scratch[self.scratch_len] = byte;
        self.scratch_len += 1;
    }

    fn finish_extension(&mut self) -> ParserFeed {
        if self.ext_type == EXT_SUPPORTED_VERSIONS {
            if self.supported_versions_seen {
                self.supported_versions_duplicate = true;
            }
            self.supported_versions_seen = true;
            // RFC 8446 §4.2.1: in ServerHello the extension payload is the
            // two-byte selected_version itself, not the ClientHello vector.
            if self.ext_len == 2
                && u16::from_be_bytes([self.ext_value_prefix[0], self.ext_value_prefix[1]])
                    == TLS_VERSION_1_3
            {
                self.supported_versions_tls13 = true;
            }
        }

        if self.extensions_remaining == 0 {
            return self.complete();
        }
        if self.extensions_remaining < 4 {
            return self.fail();
        }
        self.stage = ServerHelloStage::ExtensionHeader;
        self.scratch_len = 0;
        ParserFeed::Running
    }

    fn feed_byte(&mut self, byte: u8) -> ParserFeed {
        if matches!(
            self.stage,
            ServerHelloStage::Complete | ServerHelloStage::Invalid
        ) {
            return if self.stage == ServerHelloStage::Complete {
                ParserFeed::Complete
            } else {
                ParserFeed::Invalid
            };
        }
        if self.pos >= self.body_len {
            return self.fail();
        }
        self.pos += 1;

        match self.stage {
            ServerHelloStage::ServerVersion => {
                self.push_scratch(byte);
                if self.scratch_len == 2 {
                    self.server_version =
                        Some(u16::from_be_bytes([self.scratch[0], self.scratch[1]]));
                    self.scratch_len = 0;
                    self.skip_remaining = 32;
                    self.stage = ServerHelloStage::Random;
                }
            }
            ServerHelloStage::Random => {
                self.skip_remaining -= 1;
                if self.skip_remaining == 0 {
                    self.stage = ServerHelloStage::SessionIdLen;
                }
            }
            ServerHelloStage::SessionIdLen => {
                if byte > 32 {
                    return self.fail();
                }
                self.skip_remaining = byte as usize;
                self.stage = if byte == 0 {
                    ServerHelloStage::CipherSuite
                } else {
                    ServerHelloStage::SessionId
                };
            }
            ServerHelloStage::SessionId => {
                self.skip_remaining -= 1;
                if self.skip_remaining == 0 {
                    self.stage = ServerHelloStage::CipherSuite;
                }
            }
            ServerHelloStage::CipherSuite => {
                self.push_scratch(byte);
                if self.scratch_len == 2 {
                    self.cipher = Some(u16::from_be_bytes([self.scratch[0], self.scratch[1]]));
                    self.scratch_len = 0;
                    self.stage = ServerHelloStage::Compression;
                }
            }
            ServerHelloStage::Compression => {
                self.compression = Some(byte);
                if self.pos == self.body_len {
                    return self.complete();
                }
                if self.body_len - self.pos < 2 {
                    return self.fail();
                }
                self.stage = ServerHelloStage::ExtensionsLen;
            }
            ServerHelloStage::ExtensionsLen => {
                self.push_scratch(byte);
                if self.scratch_len == 2 {
                    let extensions_len =
                        usize::from(u16::from_be_bytes([self.scratch[0], self.scratch[1]]));
                    if self.pos + extensions_len != self.body_len {
                        return self.fail();
                    }
                    self.extensions_remaining = extensions_len;
                    self.scratch_len = 0;
                    if extensions_len == 0 {
                        return self.complete();
                    }
                    if extensions_len < 4 {
                        return self.fail();
                    }
                    self.stage = ServerHelloStage::ExtensionHeader;
                }
            }
            ServerHelloStage::ExtensionHeader => {
                self.push_scratch(byte);
                if self.scratch_len == 4 {
                    self.ext_type = u16::from_be_bytes([self.scratch[0], self.scratch[1]]);
                    self.ext_len =
                        usize::from(u16::from_be_bytes([self.scratch[2], self.scratch[3]]));
                    self.extensions_remaining -= 4;
                    if self.ext_len > self.extensions_remaining {
                        return self.fail();
                    }
                    self.ext_pos = 0;
                    self.ext_value_prefix = [0; 4];
                    self.scratch_len = 0;
                    if self.ext_len == 0 {
                        return self.finish_extension();
                    }
                    self.stage = ServerHelloStage::ExtensionBody;
                }
            }
            ServerHelloStage::ExtensionBody => {
                if self.ext_pos < self.ext_value_prefix.len() {
                    self.ext_value_prefix[self.ext_pos] = byte;
                }
                self.ext_pos += 1;
                self.extensions_remaining -= 1;
                if self.ext_pos == self.ext_len {
                    return self.finish_extension();
                }
            }
            ServerHelloStage::Complete | ServerHelloStage::Invalid => unreachable!(),
        }

        if self.pos == self.body_len
            && !matches!(
                self.stage,
                ServerHelloStage::Complete | ServerHelloStage::Invalid
            )
        {
            return self.fail();
        }
        match self.stage {
            ServerHelloStage::Complete => ParserFeed::Complete,
            ServerHelloStage::Invalid => ParserFeed::Invalid,
            _ => ParserFeed::Running,
        }
    }

    fn outcome(&self) -> ServerHelloOutcome {
        let tls13_supported = self.stage == ServerHelloStage::Complete
            && self.server_version == Some(TLS_VERSION_1_2)
            && self.compression == Some(0)
            && self.supported_versions_seen
            && self.supported_versions_tls13
            && !self.supported_versions_duplicate;
        ServerHelloOutcome {
            tls13_supported,
            cipher: self.cipher,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakePhase {
    Header,
    Body,
}

/// Incremental handshake-message stream layered over handshake records.
/// Message fragments may span records; non-handshake records interleaved in
/// the middle of a message make that message inconclusive.
struct HandshakeScanner {
    phase: HandshakePhase,
    header: [u8; 4],
    header_len: usize,
    msg_len: usize,
    msg_pos: usize,
    parser: Option<ServerHelloParser>,
    serverhello_seen: bool,
    serverhello_decided: bool,
    outcome: Option<ServerHelloOutcome>,
    found_client_hello: bool,
}

impl HandshakeScanner {
    fn new() -> Self {
        Self {
            phase: HandshakePhase::Header,
            header: [0; 4],
            header_len: 0,
            msg_len: 0,
            msg_pos: 0,
            parser: None,
            serverhello_seen: false,
            serverhello_decided: false,
            outcome: None,
            found_client_hello: false,
        }
    }

    fn decide_serverhello(&mut self, parser: &ServerHelloParser) {
        if self.serverhello_decided {
            return;
        }
        self.serverhello_decided = true;
        self.outcome = Some(parser.outcome());
    }

    fn finish_message(&mut self) {
        if let Some(parser) = self.parser.take() {
            self.decide_serverhello(&parser);
        }
        self.phase = HandshakePhase::Header;
        self.header_len = 0;
        self.msg_len = 0;
        self.msg_pos = 0;
    }

    fn abort_open_message(&mut self) {
        if self.serverhello_decided {
            return;
        }
        if self.phase == HandshakePhase::Body {
            if let Some(parser) = self.parser.take() {
                self.decide_serverhello(&parser);
            }
        }
        self.phase = HandshakePhase::Header;
        self.header_len = 0;
        self.msg_len = 0;
        self.msg_pos = 0;
    }

    fn feed_byte(&mut self, byte: u8) {
        if self.serverhello_decided {
            return;
        }
        match self.phase {
            HandshakePhase::Header => {
                if self.header_len == 0 && byte == TLS_CLIENT_HELLO {
                    self.found_client_hello = true;
                }
                self.header[self.header_len] = byte;
                self.header_len += 1;
                if self.header_len < self.header.len() {
                    return;
                }
                let msg_type = self.header[0];
                self.msg_len = ((self.header[1] as usize) << 16)
                    | ((self.header[2] as usize) << 8)
                    | self.header[3] as usize;
                self.msg_pos = 0;
                if msg_type == TLS_CLIENT_HELLO {
                    self.found_client_hello = true;
                }
                if msg_type == TLS_SERVER_HELLO {
                    self.serverhello_seen = true;
                    self.parser = Some(ServerHelloParser::new(self.msg_len));
                }
                if self.msg_len == 0 {
                    self.finish_message();
                } else {
                    self.phase = HandshakePhase::Body;
                }
            }
            HandshakePhase::Body => {
                if let Some(parser) = &mut self.parser {
                    match parser.feed_byte(byte) {
                        ParserFeed::Running => {}
                        ParserFeed::Complete | ParserFeed::Invalid => {
                            let parser = self.parser.take().expect("parser checked above");
                            self.decide_serverhello(&parser);
                        }
                    }
                }
                self.msg_pos += 1;
                if self.msg_pos == self.msg_len {
                    self.finish_message();
                }
            }
        }
    }

    fn take_outcome(&mut self) -> Option<ServerHelloOutcome> {
        self.outcome.take()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScannerStep {
    Header,
    Body,
}

/// Record-aligned scanner for one direction of the inner byte stream.
struct TlsRecordScanner {
    step: ScannerStep,
    header: [u8; 5],
    header_len: usize,
    body_remaining: usize,
    handshake: HandshakeScanner,
    outcome: Option<ServerHelloOutcome>,
}

impl TlsRecordScanner {
    fn new() -> Self {
        Self {
            step: ScannerStep::Header,
            header: [0; 5],
            header_len: 0,
            body_remaining: 0,
            handshake: HandshakeScanner::new(),
            outcome: None,
        }
    }

    fn reset_record(&mut self) {
        self.step = ScannerStep::Header;
        self.header_len = 0;
        self.body_remaining = 0;
    }

    fn record_is_handshake(&self) -> bool {
        self.header[0] == TLS_HANDSHAKE && self.header[1] == TLS_MAJOR
    }

    fn begin_record(&mut self) -> bool {
        self.body_remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
        if !self.record_is_handshake() {
            self.handshake.abort_open_message();
        }
        if self.body_remaining == 0 {
            return self.finish_record();
        }
        self.step = ScannerStep::Body;
        false
    }

    /// Finish the record.  Returns whether doing so emitted the first
    /// ServerHello decision; the caller uses the position as the exact record
    /// boundary after that ServerHello.
    fn finish_record(&mut self) -> bool {
        let emitted = if let Some(outcome) = self.handshake.take_outcome() {
            self.outcome = Some(outcome);
            true
        } else {
            false
        };
        self.reset_record();
        emitted
    }

    fn feed(&mut self, chunk: &[u8]) -> Option<usize> {
        let mut serverhello_end = None;
        for (index, &byte) in chunk.iter().enumerate() {
            match self.step {
                ScannerStep::Header => {
                    self.header[self.header_len] = byte;
                    self.header_len += 1;
                    if self.header_len == self.header.len() && self.begin_record() {
                        serverhello_end = Some(index + 1);
                    }
                }
                ScannerStep::Body => {
                    if self.record_is_handshake() {
                        self.handshake.feed_byte(byte);
                    }
                    self.body_remaining -= 1;
                    if self.body_remaining == 0 && self.finish_record() {
                        serverhello_end = Some(index + 1);
                    }
                }
            }
        }
        serverhello_end
    }

    fn found_client_hello(&self) -> bool {
        self.handshake.found_client_hello
    }

    fn serverhello_seen(&self) -> bool {
        self.handshake.serverhello_seen
    }
}

/// TLS detection state shared by both directions of one Vision connection.
/// The packet budget is deliberately shared, matching xray's single
/// `NumberOfPacketToFilter` counter: uplink and downlink non-empty chunks
/// both decrement it.
pub(crate) struct TlsInspector {
    packets_left: usize,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    cipher: u16,
    client_stream: TlsRecordScanner,
    server_stream: TlsRecordScanner,
}

impl TlsInspector {
    pub(crate) fn new() -> Self {
        Self {
            packets_left: TLS_FILTER_PACKETS,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: 0,
            client_stream: TlsRecordScanner::new(),
            server_stream: TlsRecordScanner::new(),
        }
    }

    pub(crate) fn packets_left(&self) -> usize {
        self.packets_left
    }

    pub(crate) fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub(crate) fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    pub(crate) fn enable_xtls(&self) -> bool {
        self.enable_xtls
    }

    /// Count one opaque non-empty packet without hello recognition.  XUDP
    /// uses this: its payload may coincidentally look like TLS records, but
    /// Vision must never use that payload as DIRECT evidence.
    pub(crate) fn observe_opaque_packet(&mut self, chunk: &[u8]) {
        if !chunk.is_empty() && self.packets_left > 0 {
            self.packets_left -= 1;
        }
    }

    pub(crate) fn observe_client_stream(&mut self, chunk: &[u8]) {
        if chunk.is_empty() || self.packets_left == 0 {
            return;
        }
        self.packets_left -= 1;
        self.client_stream.feed(chunk);
        self.apply_scanner_flags();
    }

    /// Observe downlink bytes.  The returned index is the first byte after
    /// the record carrying the first ServerHello decision, when that record
    /// ends inside this chunk.
    pub(crate) fn observe_server_stream(&mut self, chunk: &[u8]) -> Option<usize> {
        if chunk.is_empty() || self.packets_left == 0 {
            return None;
        }
        self.packets_left -= 1;
        let serverhello_end = self.server_stream.feed(chunk);
        self.apply_scanner_flags();
        serverhello_end
    }

    fn apply_scanner_flags(&mut self) {
        if self.client_stream.found_client_hello() || self.server_stream.found_client_hello() {
            self.is_tls = true;
        }
        if self.client_stream.serverhello_seen() || self.server_stream.serverhello_seen() {
            self.is_tls = true;
            self.is_tls12_or_above = true;
        }

        for scanner in [&mut self.client_stream, &mut self.server_stream] {
            let Some(outcome) = scanner.outcome.take() else {
                continue;
            };
            self.cipher = outcome.cipher.unwrap_or(0);
            if outcome.tls13_supported
                && outcome
                    .cipher
                    .is_some_and(|cipher| TLS13_CIPHER_SUITES.contains(&cipher))
            {
                self.enable_xtls = true;
            }
            // A completed ServerHello decision is conclusive either way:
            // TLS 1.2-or-older, malformed evidence, or an excluded suite all
            // end filtering rather than consuming the rest of the budget.
            self.packets_left = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden_serverhello() -> Vec<u8> {
        let hex = "16030300520200004e0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f1302000006002b00020304";
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn extension(ext_type: u16, body: &[u8]) -> Vec<u8> {
        let mut out = ext_type.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn serverhello_record(
        session_id: &[u8],
        cipher: u16,
        extensions_vector: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut body = TLS_VERSION_1_2.to_be_bytes().to_vec();
        body.extend_from_slice(&[0x11; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        if let Some(extensions) = extensions_vector {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(extensions);
        }

        let handshake_len = 4 + body.len();
        let mut record = vec![
            TLS_HANDSHAKE,
            TLS_MAJOR,
            TLS_MAJOR,
            (handshake_len >> 8) as u8,
            handshake_len as u8,
            TLS_SERVER_HELLO,
        ];
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn serverhello_golden_cipher_and_extensions_across_single_bytes() {
        let hello = golden_serverhello();
        for split_a in 0..hello.len() {
            for split_b in split_a..hello.len() {
                let mut inspector = TlsInspector::new();
                inspector.observe_server_stream(&hello[..split_a]);
                inspector.observe_server_stream(&hello[split_a..split_b]);
                inspector.observe_server_stream(&hello[split_b..]);
                assert!(
                    inspector.enable_xtls(),
                    "split {split_a}/{split_b} must not lose the extension parse"
                );
                assert_eq!(inspector.cipher, 0x1302);
                assert_eq!(inspector.packets_left(), 0);
            }
        }
    }

    #[test]
    fn tls12_serverhello_without_supported_versions_does_not_enable_direct() {
        let hello = serverhello_record(&[], 0x1301, None);
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&hello);
        assert!(inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());
        assert_eq!(inspector.packets_left(), 0);
    }

    #[test]
    fn magic_bytes_in_random_or_session_id_are_not_extension_evidence() {
        let magic = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

        let mut random_hello = serverhello_record(&[], 0x1301, Some(&[]));
        random_hello[11..17].copy_from_slice(&magic);
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&random_hello);
        assert!(inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());

        let mut session_id = [0u8; 32];
        session_id[..magic.len()].copy_from_slice(&magic);
        let session_hello = serverhello_record(&session_id, 0x1301, Some(&[]));
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&session_hello);
        assert!(inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());
    }

    #[test]
    fn unrelated_extensions_are_walked_to_find_supported_versions() {
        let mut vector = extension(0x0015, &[1, 2, 3, 4]);
        vector.extend_from_slice(&extension(EXT_SUPPORTED_VERSIONS, &[0x03, 0x04]));
        vector.extend_from_slice(&extension(0x0033, &[0xaa; 36]));
        let hello = serverhello_record(&[0x22; 32], 0x1302, Some(&vector));
        let mut inspector = TlsInspector::new();
        let split = hello.len() - 3;
        inspector.observe_server_stream(&hello[..split]);
        inspector.observe_server_stream(&hello[split..]);
        assert!(inspector.enable_xtls());
        assert_eq!(inspector.cipher, 0x1302);
    }

    #[test]
    fn duplicate_supported_versions_is_rejected() {
        let one = extension(EXT_SUPPORTED_VERSIONS, &[0x03, 0x04]);
        let mut vector = one.clone();
        vector.extend_from_slice(&one);
        let hello = serverhello_record(&[], 0x1301, Some(&vector));
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&hello);
        assert!(inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());
        assert_eq!(inspector.packets_left(), 0);
    }

    #[test]
    fn malformed_extension_lengths_are_inconclusive_not_positive_evidence() {
        let mut vector = extension(EXT_SUPPORTED_VERSIONS, &[0x03, 0x04]);
        // The extension header claims four payload bytes while the vector
        // ends after two: a hard overrun in a real extension walk.
        vector[3] = 4;
        let hello = serverhello_record(&[], 0x1301, Some(&vector));
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&hello);
        assert!(inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());
        assert_eq!(inspector.packets_left(), 0);

        // The ClientHello length-prefixed form is not the ServerHello form.
        let vector = extension(EXT_SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]);
        let hello = serverhello_record(&[], 0x1301, Some(&vector));
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&hello);
        assert!(!inspector.enable_xtls());
    }

    #[test]
    fn serverhello_handshake_may_be_fragmented_across_tls_records() {
        let hello = serverhello_record(
            &[0x22; 32],
            0x1301,
            Some(&extension(EXT_SUPPORTED_VERSIONS, &[0x03, 0x04])),
        );
        let handshake = &hello[5..];
        let split = 17;
        let mut fragmented = vec![TLS_HANDSHAKE, TLS_MAJOR, TLS_MAJOR];
        fragmented.extend_from_slice(&(split as u16).to_be_bytes());
        fragmented.extend_from_slice(&handshake[..split]);
        fragmented.extend_from_slice(&[TLS_HANDSHAKE, TLS_MAJOR, TLS_MAJOR]);
        fragmented.extend_from_slice(&((handshake.len() - split) as u16).to_be_bytes());
        fragmented.extend_from_slice(&handshake[split..]);

        let mut inspector = TlsInspector::new();
        let chunk_split = fragmented.len() / 2;
        inspector.observe_server_stream(&fragmented[..chunk_split]);
        inspector.observe_server_stream(&fragmented[chunk_split..]);
        assert!(inspector.enable_xtls());
        assert_eq!(inspector.cipher, 0x1301);
    }

    #[test]
    fn ccm8_suite_is_in_table_but_not_in_xtls_whitelist() {
        let hello = serverhello_record(
            &[],
            0x1305,
            Some(&extension(EXT_SUPPORTED_VERSIONS, &[0x03, 0x04])),
        );
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&hello);
        assert!(inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());
        assert_eq!(inspector.packets_left(), 0);
    }

    #[test]
    fn wrong_selected_version_is_a_tls12_decision() {
        let hello = serverhello_record(
            &[],
            0x1301,
            Some(&extension(EXT_SUPPORTED_VERSIONS, &[0x03, 0x03])),
        );
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&hello);
        assert!(inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());
        assert_eq!(inspector.packets_left(), 0);
    }

    #[test]
    fn tls_like_bytes_after_a_plain_prefix_are_not_magic() {
        let mut bytes = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        bytes.extend_from_slice(&golden_serverhello());
        let mut inspector = TlsInspector::new();
        for _ in 0..TLS_FILTER_PACKETS {
            inspector.observe_server_stream(&bytes);
        }
        assert!(!inspector.enable_xtls());
    }

    #[test]
    fn packet_budget_is_shared_by_directions() {
        let mut inspector = TlsInspector::new();
        for _ in 0..TLS_FILTER_PACKETS - 1 {
            inspector.observe_client_stream(b"x");
        }
        assert_eq!(inspector.packets_left(), 1);
        inspector.observe_server_stream(&golden_serverhello());
        assert!(
            inspector.enable_xtls(),
            "the eighth packet is still examined"
        );
        assert_eq!(inspector.packets_left(), 0);
    }

    #[test]
    fn opaque_packets_count_without_recognizing_hellos() {
        let mut inspector = TlsInspector::new();
        inspector.observe_opaque_packet(&golden_serverhello());
        assert_eq!(inspector.packets_left(), TLS_FILTER_PACKETS - 1);
        assert!(!inspector.is_tls());
        assert!(!inspector.enable_xtls());
    }

    #[test]
    fn client_hello_record_sets_tls_without_direct_evidence() {
        let hello = [0x16, 0x03, 0x01, 0x00, 0x01, 0x01];
        let mut inspector = TlsInspector::new();
        inspector.observe_client_stream(&hello);
        assert!(inspector.is_tls());
        assert!(!inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());
    }
}
