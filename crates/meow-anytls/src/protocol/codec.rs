use crate::protocol::frame::{Command, Frame, HEADER_OVERHEAD_SIZE};
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/// Frame codec for encoding and decoding AnyTLS frames
pub struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        use bytes::Buf;

        // Need at least header size to decode
        if src.len() < HEADER_OVERHEAD_SIZE {
            tracing::trace!(
                "[FrameCodec] decode: Not enough data for header (have {}, need {})",
                src.len(),
                HEADER_OVERHEAD_SIZE
            );
            return Ok(None);
        }

        // Save position before parsing header
        let before_header = src.len();

        // Parse header WITHOUT consuming bytes (use peek methods)
        // We'll only consume them if we have enough payload
        let mut header_reader = &src[..HEADER_OVERHEAD_SIZE];
        let cmd_byte = header_reader.get_u8();
        let cmd = Command::from(cmd_byte);
        let stream_id = header_reader.get_u32();
        let data_len = header_reader.get_u16() as usize;

        // Keep the preview as a borrowed tracing field. Formatting it eagerly
        // allocated a String for every decoded frame even when debug logs were
        // disabled.
        tracing::trace!(
            preview = ?&src[..src.len().min(20)],
            "[FrameCodec] decode: Parsing header (buffer had {} bytes)",
            before_header,
        );
        tracing::trace!(
            "[FrameCodec] decode: Parsed header cmd={:?} (byte={}), stream_id={}, data_len={}",
            cmd,
            cmd_byte,
            stream_id,
            data_len
        );

        // Check if we have enough data (header + payload)
        let total_needed = HEADER_OVERHEAD_SIZE + data_len;
        if src.len() < total_needed {
            tracing::trace!(
                "[FrameCodec] decode: Not enough data for complete frame (have {}, need {})",
                src.len(),
                total_needed
            );
            // Reserve space for the remaining data
            src.reserve(total_needed - src.len());
            return Ok(None);
        }

        // Now consume the header and payload
        src.advance(HEADER_OVERHEAD_SIZE);

        // Extract data
        let data = if data_len > 0 {
            src.split_to(data_len).freeze()
        } else {
            Bytes::new()
        };

        tracing::trace!(
            "[FrameCodec] decode: Successfully decoded frame cmd={:?}, stream_id={}, data_len={}",
            cmd,
            stream_id,
            data_len
        );

        Ok(Some(Frame {
            cmd,
            stream_id,
            data,
        }))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data_len = item.data.len();
        if data_len > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS frame payload exceeds u16 length",
            ));
        }

        // Reserve space: header + data
        dst.reserve(HEADER_OVERHEAD_SIZE + data_len);

        // Write header
        dst.put_u8(item.cmd.into());
        dst.put_u32(item.stream_id);
        dst.put_u16(data_len as u16);

        // Write data
        if !item.data.is_empty() {
            dst.extend_from_slice(&item.data);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_frame_is_rejected_without_modifying_output() {
        let mut output = BytesMut::from(&b"prefix"[..]);
        let frame = Frame::data(1, Bytes::from(vec![0; u16::MAX as usize + 1]));
        assert_eq!(
            FrameCodec.encode(frame, &mut output).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(&output[..], b"prefix");
    }

    #[tokio::test]
    async fn test_encode_decode() {
        let mut codec = FrameCodec;
        let frame = Frame::data(123, Bytes::from("hello world"));

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.cmd, frame.cmd);
        assert_eq!(decoded.stream_id, frame.stream_id);
        assert_eq!(decoded.data, frame.data);
    }

    #[tokio::test]
    async fn test_encode_decode_control_frame() {
        let mut codec = FrameCodec;
        let frame = Frame::control(Command::Syn, 456);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn test_decode_incomplete_frame() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::from(&[1u8, 0, 0, 0, 0][..]); // Only 5 bytes, need 7

        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[tokio::test]
    async fn test_decode_incomplete_data() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        buf.put_u8(Command::Push as u8);
        buf.put_u32(789);
        buf.put_u16(100); // Claims 100 bytes data
        buf.put_u8(0); // But only 1 byte available

        let result = codec.decode(&mut buf);
        assert!(result.unwrap().is_none()); // Should return None, not error
    }
}
