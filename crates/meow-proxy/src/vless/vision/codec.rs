//! Role-independent XTLS Vision padding-frame codec.
//!
//! This module owns only the wire layout and the frame-boundary state
//! machine.  Client and server policy — TLS filtering, DIRECT eligibility,
//! and raw-transport switching — lives in the role-specific modules.

use rand::RngCore;

pub(crate) const UUID_LEN: usize = 16;
pub(crate) const PADDING_HEADER_LEN: usize = UUID_LEN + 1 + 2 + 2;
pub(crate) const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub(crate) const COMMAND_PADDING_END: u8 = 0x01;
pub(crate) const COMMAND_PADDING_DIRECT: u8 = 0x02;
pub(crate) const TLS_HANDSHAKE: u8 = 0x16;
pub(crate) const TLS_APPLICATION_DATA: u8 = 0x17;
pub(crate) const TLS_MAJOR: u8 = 0x03;
pub(crate) const TLS_CLIENT_HELLO: u8 = 0x01;
pub(crate) const TLS_SERVER_HELLO: u8 = 0x02;
pub(crate) const TLS13_SUPPORTED_VERSIONS_EXT: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
pub(crate) const TLS13_CIPHER_SUITES: [u16; 4] = [0x1301, 0x1302, 0x1303, 0x1304];
pub(crate) const TLS_FILTER_PACKETS: usize = 8;

/// xray sizes its vision buffers at 8192 bytes and caps padding so the
/// whole frame — maximal 21-byte header included — fits one such buffer.
/// The cap formula keeps that shape even though meow's own padding-length
/// rules never reach it: long padding totals under 1400 bytes and content
/// at or above 900 bytes is unpadded, so the cap is defence in depth.
pub(crate) const XRAY_BUFFER_SIZE: usize = 8192;
pub(crate) const XRAY_PADDING_CONTENT_CAP: usize = XRAY_BUFFER_SIZE - PADDING_HEADER_LEN;
/// Server write frames carry at most one 16 KiB content slice: the spec's
/// hot-path contract budgets exactly one reusable pending frame of that
/// size.  The u16 length fields would allow more, and both xray and mihomo
/// readers accept oversized content incrementally, but bounding the frame
/// bounds the reusable allocation.
pub(crate) const FRAME_CONTENT_CAP: usize = 16 * 1024;
pub(crate) const PADDING_SCRATCH_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PaddingCommand {
    Continue,
    End,
    Direct,
}

impl TryFrom<u8> for PaddingCommand {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            COMMAND_PADDING_CONTINUE => Ok(Self::Continue),
            COMMAND_PADDING_END => Ok(Self::End),
            COMMAND_PADDING_DIRECT => Ok(Self::Direct),
            other => Err(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PaddingFrameHeader {
    pub(crate) uuid: Option<[u8; UUID_LEN]>,
    pub(crate) command: u8,
    pub(crate) content_len: usize,
    pub(crate) padding_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PaddingReadPhase {
    Header {
        need_uuid: bool,
    },
    Content {
        command: u8,
        remaining_content: usize,
        remaining_padding: usize,
    },
    Padding {
        command: u8,
        remaining_padding: usize,
    },
    Through,
    Eof,
}

/// Fixed-scratch incremental padding-frame reader.
///
/// The header scratch is 21 bytes independent of the peer's length fields;
/// content is copied by the role-specific reader directly into its output
/// buffer and padding is discarded through a fixed scratch there.
pub(crate) struct PaddingReader {
    header: [u8; PADDING_HEADER_LEN],
    header_filled: usize,
    phase: PaddingReadPhase,
}

impl PaddingReader {
    pub(crate) fn new() -> Self {
        Self {
            header: [0; PADDING_HEADER_LEN],
            header_filled: 0,
            phase: PaddingReadPhase::Header { need_uuid: true },
        }
    }

    pub(crate) fn phase(&self) -> PaddingReadPhase {
        self.phase
    }

    pub(crate) fn set_eof(&mut self) {
        self.phase = PaddingReadPhase::Eof;
    }

    pub(crate) fn header_filled(&self) -> usize {
        self.header_filled
    }

    fn header_need(need_uuid: bool) -> usize {
        if need_uuid {
            PADDING_HEADER_LEN
        } else {
            PADDING_HEADER_LEN - UUID_LEN
        }
    }

    /// Remaining header bytes.  The caller must only use this in the
    /// `Header` phase; the codec itself is crate-private, so a debug assert
    /// is sufficient for the internal contract.
    pub(crate) fn header_write_buf(&mut self) -> &mut [u8] {
        let PaddingReadPhase::Header { need_uuid } = self.phase else {
            debug_assert!(false, "header_write_buf outside header phase");
            return &mut [];
        };
        let need = Self::header_need(need_uuid);
        &mut self.header[self.header_filled..need]
    }

    pub(crate) fn note_header_bytes(&mut self, n: usize) {
        self.header_filled += n;
    }

    pub(crate) fn header_complete(&self) -> bool {
        match self.phase {
            PaddingReadPhase::Header { need_uuid } => {
                self.header_filled == Self::header_need(need_uuid)
            }
            _ => false,
        }
    }

    /// Consume the completed fixed-size header and enter the content/padding
    /// phase described by it.  UUID verification is role policy and is left
    /// to the caller.
    pub(crate) fn finish_header(&mut self) -> PaddingFrameHeader {
        let PaddingReadPhase::Header { need_uuid } = self.phase else {
            unreachable!("finish_header outside header phase");
        };
        debug_assert!(self.header_complete());

        let (uuid, offset) = if need_uuid {
            let mut uuid = [0u8; UUID_LEN];
            uuid.copy_from_slice(&self.header[..UUID_LEN]);
            (Some(uuid), UUID_LEN)
        } else {
            (None, 0)
        };
        let command = self.header[offset];
        let content_len =
            u16::from_be_bytes([self.header[offset + 1], self.header[offset + 2]]) as usize;
        let padding_len =
            u16::from_be_bytes([self.header[offset + 3], self.header[offset + 4]]) as usize;

        self.header_filled = 0;
        self.phase = if content_len == 0 {
            PaddingReadPhase::Padding {
                command,
                remaining_padding: padding_len,
            }
        } else {
            PaddingReadPhase::Content {
                command,
                remaining_content: content_len,
                remaining_padding: padding_len,
            }
        };

        PaddingFrameHeader {
            uuid,
            command,
            content_len,
            padding_len,
        }
    }

    pub(crate) fn consume_content(&mut self, n: usize) {
        let PaddingReadPhase::Content {
            command,
            remaining_content,
            remaining_padding,
        } = self.phase
        else {
            debug_assert!(false, "consume_content outside content phase");
            return;
        };
        debug_assert!(n <= remaining_content);
        let remaining_content = remaining_content - n;
        self.phase = if remaining_content == 0 {
            PaddingReadPhase::Padding {
                command,
                remaining_padding,
            }
        } else {
            PaddingReadPhase::Content {
                command,
                remaining_content,
                remaining_padding,
            }
        };
    }

    pub(crate) fn consume_padding(&mut self, n: usize) {
        let PaddingReadPhase::Padding {
            command,
            remaining_padding,
        } = self.phase
        else {
            debug_assert!(false, "consume_padding outside padding phase");
            return;
        };
        debug_assert!(n <= remaining_padding);
        self.phase = PaddingReadPhase::Padding {
            command,
            remaining_padding: remaining_padding - n,
        };
    }

    /// Finish a frame after its declared content and padding have both been
    /// consumed.  Unknown commands are reported without changing state; the
    /// role-specific caller closes the connection in that case.
    pub(crate) fn complete_frame(&mut self, command: u8) -> Result<PaddingCommand, u8> {
        let parsed = PaddingCommand::try_from(command)?;
        self.phase = match parsed {
            PaddingCommand::Continue => PaddingReadPhase::Header { need_uuid: false },
            PaddingCommand::End | PaddingCommand::Direct => PaddingReadPhase::Through,
        };
        Ok(parsed)
    }
}

/// Padding-length rule shared by the client and server writers: TLS-shaped
/// short payloads are long-padded into `[900,1400)` total bytes, non-TLS
/// short payloads get `rand % 256`, and payloads at or above 900 bytes are
/// unpadded (the mihomo-compatible behavior of the existing client).
pub(crate) fn generated_padding_len(content_len: usize, long_padding: bool) -> usize {
    if content_len < 900 {
        let mut rng = rand::rng();
        if long_padding {
            (rng.next_u32() as usize % 500) + 900 - content_len
        } else {
            rng.next_u32() as usize % 256
        }
    } else {
        0
    }
}

/// Apply xray's hard frame cap: `8192 - 21 - contentLen`.  The 21-byte
/// reservation is used even after the UUID has left the wire.
pub(crate) fn capped_padding_len(content_len: usize, long_padding: bool) -> usize {
    generated_padding_len(content_len, long_padding)
        .min(XRAY_PADDING_CONTENT_CAP.saturating_sub(content_len))
}

/// Incremental boundary tracker for the inner TLS record stream after the
/// ServerHello record.  `17 03 03` records with non-zero bodies build an
/// eligibility streak; any other record type breaks the current write batch's
/// eligibility but does not lose byte alignment, so a record fragmented over
/// several writes can still complete and earn DIRECT later.
#[derive(Clone, Copy)]
pub(crate) struct TlsAppRecordTracker {
    active: bool,
    header: [u8; 5],
    header_len: usize,
    body_remaining: usize,
    record_valid: bool,
    complete_streak: bool,
    batch_valid: bool,
}

impl TlsAppRecordTracker {
    pub(crate) fn new() -> Self {
        Self {
            active: false,
            header: [0; 5],
            header_len: 0,
            body_remaining: 0,
            record_valid: false,
            complete_streak: false,
            batch_valid: true,
        }
    }

    /// Start tracking exactly at the record boundary that ends the inner
    /// ServerHello record.
    pub(crate) fn activate(&mut self) {
        *self = Self {
            active: true,
            ..Self::new()
        };
    }

    pub(crate) fn active(&self) -> bool {
        self.active
    }

    fn at_record_boundary(&self) -> bool {
        self.header_len == 0 && self.body_remaining == 0
    }

    fn feed_byte(&mut self, byte: u8) {
        if self.body_remaining > 0 {
            self.body_remaining -= 1;
            if self.body_remaining == 0 && self.record_valid {
                self.complete_streak = true;
            }
            return;
        }

        self.header[self.header_len] = byte;
        self.header_len += 1;
        if self.header_len < self.header.len() {
            return;
        }

        let record_len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
        self.record_valid = self.header[0] == TLS_APPLICATION_DATA
            && self.header[1] == TLS_MAJOR
            && self.header[2] == TLS_MAJOR
            && record_len != 0;
        if !self.record_valid {
            self.batch_valid = false;
            self.complete_streak = false;
        }
        self.header_len = 0;
        self.body_remaining = record_len;
    }

    /// Feed one accepted write batch and report whether it ends at a complete
    /// application-data record boundary without a foreign record in this
    /// batch.  Bytes may continue a record started by an earlier batch: the
    /// boundary property belongs to the byte stream, not to the arbitrary
    /// write slicing.
    pub(crate) fn feed_batch(&mut self, chunk: &[u8]) -> bool {
        if !self.active || chunk.is_empty() {
            return false;
        }
        self.batch_valid = true;
        for &byte in chunk {
            self.feed_byte(byte);
        }
        self.batch_valid && self.complete_streak && self.at_record_boundary()
    }

    /// Largest record-boundary cut not past `cap` from the current stream
    /// position.  If even the first boundary is beyond the cap, fall back to
    /// the flat cap; the stateful tracker will still recognize the record
    /// when a later batch completes it.
    pub(crate) fn aligned_cut(&self, buf: &[u8], cap: usize) -> usize {
        debug_assert!(cap > 0);
        if buf.len() <= cap {
            return buf.len();
        }
        let mut probe = *self;
        let mut last_boundary = 0usize;
        for (index, &byte) in buf.iter().take(cap).enumerate() {
            probe.feed_byte(byte);
            if probe.at_record_boundary() {
                last_boundary = index + 1;
            }
        }
        if last_boundary == 0 {
            cap
        } else {
            last_boundary
        }
    }
}

pub(crate) fn encode_padding_frame_with_padding_len(
    dst: &mut Vec<u8>,
    command: u8,
    user_uuid: Option<&[u8; UUID_LEN]>,
    content: &[u8],
    padding_len: usize,
) {
    debug_assert!(u16::try_from(content.len()).is_ok());
    debug_assert!(u16::try_from(padding_len).is_ok());
    if let Some(uuid) = user_uuid {
        dst.extend_from_slice(uuid);
    }
    dst.push(command);
    dst.extend_from_slice(&(content.len() as u16).to_be_bytes());
    dst.extend_from_slice(&(padding_len as u16).to_be_bytes());
    dst.extend_from_slice(content);
    dst.resize(dst.len() + padding_len, 0);
}

pub(crate) fn build_padding_frame(
    command: u8,
    user_uuid: Option<&[u8; UUID_LEN]>,
    content: &[u8],
    padding_tls: bool,
) -> Vec<u8> {
    let padding_len = generated_padding_len(content.len(), padding_tls);
    let header_len = if user_uuid.is_some() {
        PADDING_HEADER_LEN
    } else {
        PADDING_HEADER_LEN - UUID_LEN
    };
    let mut frame = Vec::with_capacity(header_len + content.len() + padding_len);
    encode_padding_frame_with_padding_len(&mut frame, command, user_uuid, content, padding_len);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![TLS_APPLICATION_DATA, TLS_MAJOR, TLS_MAJOR];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn tracker_accepts_records_fragmented_across_batches() {
        let first = app_record(b"hello");
        let second = app_record(b"world!");
        let split = 3;
        let mut tracker = TlsAppRecordTracker::new();
        tracker.activate();

        assert!(!tracker.feed_batch(&first[..split]));
        let mut remainder = first[split..].to_vec();
        remainder.extend_from_slice(&second);
        assert!(tracker.feed_batch(&remainder));
    }

    #[test]
    fn tracker_rejects_foreign_and_zero_length_records_for_the_batch() {
        let mut tracker = TlsAppRecordTracker::new();
        tracker.activate();

        let mut batch = app_record(b"data");
        batch.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        batch.extend_from_slice(&app_record(b"recovered"));
        assert!(!tracker.feed_batch(&batch));
        assert!(tracker.feed_batch(&app_record(b"next batch")));

        let mut tracker = TlsAppRecordTracker::new();
        tracker.activate();
        assert!(!tracker.feed_batch(&app_record(b"")));
        assert!(tracker.feed_batch(&app_record(b"valid afterwards")));
    }

    #[test]
    fn tracker_aligned_cut_prefers_the_last_boundary_within_cap() {
        let mut buf = app_record(&[0u8; 100]);
        buf.extend(app_record(&[0u8; 100]));
        buf.extend(app_record(&[0u8; 100]));
        let mut tracker = TlsAppRecordTracker::new();
        tracker.activate();
        // Each record is 105 bytes; cap 220 fits exactly two.
        assert_eq!(tracker.aligned_cut(&buf, 220), 210);
        assert_eq!(tracker.aligned_cut(&buf, 210), 210);
        assert_eq!(tracker.aligned_cut(&buf, 1000), buf.len());
    }

    #[test]
    fn tracker_aligned_cut_falls_back_when_first_record_exceeds_cap() {
        let buf = app_record(&[0u8; 500]);
        let mut tracker = TlsAppRecordTracker::new();
        tracker.activate();
        assert_eq!(tracker.aligned_cut(&buf, 100), 100);
    }

    #[test]
    fn padding_len_rules_match_the_frozen_contract() {
        // Long padding: content + padding lands in [900, 1400).
        for content_len in [0usize, 1, 100, 899] {
            for _ in 0..64 {
                let padding = generated_padding_len(content_len, true);
                assert!(
                    (900..1400).contains(&(content_len + padding)),
                    "content {content_len} padding {padding}"
                );
            }
        }
        // Short non-TLS padding: [0, 256).
        for _ in 0..64 {
            assert!(generated_padding_len(100, false) < 256);
        }
        // At or above 900 bytes nothing is padded (mihomo-compatible).
        assert_eq!(generated_padding_len(900, true), 0);
        assert_eq!(generated_padding_len(16 * 1024, false), 0);
        // The xray frame cap formula is structurally unreachable with these
        // rules but must still apply cleanly to hypothetical inputs.
        assert!(capped_padding_len(100, true) < 1400);
        assert_eq!(capped_padding_len(9000, true), 0);
    }
}
