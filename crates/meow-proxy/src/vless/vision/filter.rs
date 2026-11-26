//! Incremental inner-TLS recognition shared by Vision server roles.
//!
//! xray and mihomo inspect the prefix of whatever buffer the socket happened
//! to return.  This scanner is deliberately stronger: it follows TLS record
//! boundaries across arbitrary chunking, keeps only fixed scratch, and can
//! therefore not miss the `supported_versions` bytes merely because they
//! straddle two reads.

use super::codec::{
    TLS13_CIPHER_SUITES, TLS13_SUPPORTED_VERSIONS_EXT, TLS_FILTER_PACKETS, TLS_HANDSHAKE,
    TLS_MAJOR, TLS_SERVER_HELLO,
};

const SERVER_HELLO_PREFIX_LEN: usize = 79;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServerHelloOutcome {
    magic_found: bool,
    cipher: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScannerStep {
    Header,
    Body,
    Done,
}

/// Record-aligned scanner for one direction of the inner byte stream.
/// Scanning is byte-oriented and allocation-free; the small prefix copy
/// exists only for xray's cipher-offset calculus (`b[43]`,
/// `b[43+sidLen+1..+3]`) which is defined relative to the record start.
struct TlsRecordScanner {
    step: ScannerStep,
    header: [u8; 5],
    header_len: usize,
    record_len: usize,
    body_remaining: usize,
    body_pos: usize,
    prefix: [u8; SERVER_HELLO_PREFIX_LEN],
    prefix_len: usize,
    magic_window: [u8; TLS13_SUPPORTED_VERSIONS_EXT.len()],
    magic_len: usize,
    serverhello_candidate: bool,
    magic_found: bool,
    serverhello_seen: bool,
    found_client_hello: bool,
    outcome: Option<ServerHelloOutcome>,
}

impl TlsRecordScanner {
    fn new() -> Self {
        Self {
            step: ScannerStep::Header,
            header: [0; 5],
            header_len: 0,
            record_len: 0,
            body_remaining: 0,
            body_pos: 0,
            prefix: [0; SERVER_HELLO_PREFIX_LEN],
            prefix_len: 0,
            magic_window: [0; TLS13_SUPPORTED_VERSIONS_EXT.len()],
            magic_len: 0,
            serverhello_candidate: false,
            magic_found: false,
            serverhello_seen: false,
            found_client_hello: false,
            outcome: None,
        }
    }

    fn reset_record(&mut self) {
        self.step = ScannerStep::Header;
        self.header_len = 0;
        self.record_len = 0;
        self.body_remaining = 0;
        self.body_pos = 0;
        self.prefix_len = 0;
        self.magic_len = 0;
        self.serverhello_candidate = false;
        self.magic_found = false;
    }

    fn begin_record(&mut self) {
        self.record_len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
        self.prefix[..5].copy_from_slice(&self.header);
        self.prefix_len = 5;
        self.magic_len = 0;
        for byte in self.header {
            self.push_magic_byte(byte);
        }
        self.body_remaining = self.record_len;
        self.body_pos = 0;
        self.serverhello_candidate = false;
        self.magic_found = false;
        if self.record_len == 0 {
            self.finish_record();
        } else {
            self.step = ScannerStep::Body;
        }
    }

    fn push_magic_byte(&mut self, byte: u8) {
        if self.magic_len < TLS13_SUPPORTED_VERSIONS_EXT.len() {
            self.magic_window[self.magic_len] = byte;
            self.magic_len += 1;
        } else {
            self.magic_window.rotate_left(1);
            self.magic_window[TLS13_SUPPORTED_VERSIONS_EXT.len() - 1] = byte;
        }
        if self.magic_len == TLS13_SUPPORTED_VERSIONS_EXT.len()
            && self.magic_window == TLS13_SUPPORTED_VERSIONS_EXT
        {
            self.magic_found = true;
        }
    }

    fn finish_record(&mut self) {
        if self.serverhello_candidate {
            let cipher = if self.record_len + 5 >= SERVER_HELLO_PREFIX_LEN
                && self.prefix_len >= SERVER_HELLO_PREFIX_LEN
            {
                extract_serverhello_cipher(&self.prefix)
            } else {
                None
            };
            self.outcome = Some(ServerHelloOutcome {
                magic_found: self.magic_found,
                cipher,
            });
            self.step = ScannerStep::Done;
        } else {
            self.reset_record();
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            match self.step {
                ScannerStep::Done => break,
                ScannerStep::Header => {
                    self.header[self.header_len] = byte;
                    self.header_len += 1;
                    if self.header_len == self.header.len() {
                        self.begin_record();
                    }
                }
                ScannerStep::Body => {
                    if self.prefix_len < SERVER_HELLO_PREFIX_LEN {
                        self.prefix[self.prefix_len] = byte;
                        self.prefix_len += 1;
                    }
                    if self.body_pos == 0 {
                        if self.header[0] == TLS_HANDSHAKE
                            && self.header[1] == TLS_MAJOR
                            && byte == super::codec::TLS_CLIENT_HELLO
                        {
                            self.found_client_hello = true;
                        }
                        self.serverhello_candidate = self.header[0] == TLS_HANDSHAKE
                            && self.header[1] == TLS_MAJOR
                            && self.header[2] == TLS_MAJOR
                            && byte == TLS_SERVER_HELLO;
                        if self.serverhello_candidate {
                            self.serverhello_seen = true;
                        }
                    }
                    if self.serverhello_candidate {
                        self.push_magic_byte(byte);
                    }
                    self.body_pos += 1;
                    self.body_remaining -= 1;
                    if self.body_remaining == 0 {
                        self.finish_record();
                    }
                }
            }
        }
    }
}

fn extract_serverhello_cipher(prefix: &[u8; SERVER_HELLO_PREFIX_LEN]) -> Option<u16> {
    let session_id_len = prefix[43] as usize;
    let cipher_offset = 43 + session_id_len + 1;
    let bytes = prefix.get(cipher_offset..cipher_offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
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

    pub(crate) fn observe_server_stream(&mut self, chunk: &[u8]) {
        if chunk.is_empty() || self.packets_left == 0 {
            return;
        }
        self.packets_left -= 1;
        self.server_stream.feed(chunk);
        self.apply_scanner_flags();
    }

    fn apply_scanner_flags(&mut self) {
        if self.client_stream.found_client_hello || self.server_stream.found_client_hello {
            self.is_tls = true;
        }
        if self.client_stream.serverhello_seen || self.server_stream.serverhello_seen {
            self.is_tls = true;
            self.is_tls12_or_above = true;
        }

        for scanner in [&mut self.client_stream, &mut self.server_stream] {
            let Some(outcome) = scanner.outcome.take() else {
                continue;
            };
            self.cipher = outcome.cipher.unwrap_or(0);
            if outcome.magic_found {
                if outcome
                    .cipher
                    .is_some_and(|cipher| TLS13_CIPHER_SUITES.contains(&cipher))
                {
                    self.enable_xtls = true;
                }
                // xray stops filtering even when the suite was recognised
                // but excluded from XTLS (notably 0x1305): the server hello
                // is conclusive either way.
                self.packets_left = 0;
            } else {
                // A complete server hello without supported_versions is a
                // TLS 1.2-or-older decision, also conclusive.
                self.packets_left = 0;
            }
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

    #[test]
    fn serverhello_golden_cipher_and_magic_across_single_bytes() {
        let hello = golden_serverhello();
        for split_a in 0..hello.len() {
            for split_b in split_a..hello.len() {
                let mut inspector = TlsInspector::new();
                inspector.observe_server_stream(&hello[..split_a]);
                inspector.observe_server_stream(&hello[split_a..split_b]);
                inspector.observe_server_stream(&hello[split_b..]);
                assert!(
                    inspector.enable_xtls(),
                    "split {split_a}/{split_b} must not lose the cross-buffer magic"
                );
                assert_eq!(inspector.cipher, 0x1302);
                assert_eq!(inspector.packets_left(), 0);
            }
        }
    }

    #[test]
    fn ccm8_suite_is_in_table_but_not_in_xtls_whitelist() {
        let mut hello = golden_serverhello();
        hello[76] = 0x13;
        hello[77] = 0x05;
        let mut inspector = TlsInspector::new();
        inspector.observe_server_stream(&hello);
        assert!(inspector.is_tls12_or_above());
        assert!(!inspector.enable_xtls());
        assert_eq!(inspector.packets_left(), 0);
    }

    #[test]
    fn missing_supported_versions_is_a_tls12_decision() {
        let mut hello = golden_serverhello();
        let magic = TLS13_SUPPORTED_VERSIONS_EXT;
        let pos = hello.windows(magic.len()).position(|w| w == magic).unwrap();
        hello[pos + 5] = 0x03; // advertise TLS 1.2 in the extension value bytes
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
