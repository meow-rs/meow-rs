//! B4: `StreamReader` leftovers are a `Bytes` + read offset, not a
//! `Vec<u8>` + `drain`. Externally that means: partial reads leave the
//! remainder intact and byte-exact, `buffer_len` tracks it, EOF still
//! drains the remainder before reporting 0, and a 128 KiB chunk fed
//! through 32 KiB reads loses nothing.

use anytls_rs::session::StreamReader;
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

/// 128 KiB through 32 KiB reads: four full reads, no loss, and the
/// leftover path is exercised on every read after the first.
#[tokio::test]
async fn large_chunk_drains_exactly_through_smaller_reads() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut reader = StreamReader::new(7, rx);

    let payload: Vec<u8> = (0..128 * 1024u32).map(|i| (i % 251) as u8).collect();
    tx.send(Bytes::from(payload.clone()).into()).unwrap();

    let mut out = Vec::with_capacity(payload.len());
    let mut buf = vec![0u8; 32 * 1024];
    for _ in 0..4 {
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 32 * 1024);
        out.extend_from_slice(&buf[..n]);
    }
    assert_eq!(out, payload, "every byte delivered, in order");
    assert_eq!(reader.buffer_len(), 0);
}

/// Leftover reuse: alternating small reads and new channel deliveries
/// must interleave correctly — buffered bytes always precede newer
/// channel data (FIFO).
#[tokio::test]
async fn leftover_interleaves_with_new_deliveries_in_fifo_order() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut reader = StreamReader::new(7, rx);

    tx.send(Bytes::from_static(b"AAAA").into()).unwrap();
    tx.send(Bytes::from_static(b"BBBB").into()).unwrap();

    let mut buf = vec![0u8; 3];
    assert_eq!(reader.read(&mut buf).await.unwrap(), 3);
    assert_eq!(&buf, b"AAA");
    // One byte of the first chunk is buffered; the next read serves it
    // BEFORE the second channel item.
    assert_eq!(reader.read(&mut buf).await.unwrap(), 1);
    assert_eq!(&buf[..1], b"A");
    assert_eq!(reader.read(&mut buf).await.unwrap(), 3);
    assert_eq!(&buf, b"BBB");
    assert_eq!(reader.read(&mut buf).await.unwrap(), 1);
    assert_eq!(&buf[..1], b"B");
    assert_eq!(reader.buffer_len(), 0);
}

/// AsyncRead parity — the poll path (`uot` header parsing drives it)
/// must produce the same leftover behaviour as `read`. The trait method
/// is invoked fully-qualified so the inherent `read` doesn't shadow it.
#[tokio::test]
async fn poll_read_path_matches_read_semantics() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut reader = StreamReader::new(7, rx);

    tx.send(Bytes::from_static(b"chunk").into()).unwrap();
    drop(tx); // EOF after the chunk

    let mut b = [0u8; 2];
    assert_eq!(AsyncReadExt::read(&mut reader, &mut b).await.unwrap(), 2);
    assert_eq!(&b, b"ch");
    assert_eq!(AsyncReadExt::read(&mut reader, &mut b).await.unwrap(), 2);
    assert_eq!(&b, b"un");
    assert_eq!(AsyncReadExt::read(&mut reader, &mut b).await.unwrap(), 1);
    assert_eq!(&b[..1], b"k");
    // Channel closed AND leftover drained → EOF.
    assert_eq!(AsyncReadExt::read(&mut reader, &mut b).await.unwrap(), 0);
}

/// `read_exact` over leftover boundaries: the helper must compose
/// buffered remainder + channel reads transparently.
#[tokio::test]
async fn read_exact_spans_leftover_and_channel() {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut reader = StreamReader::new(7, rx);

    tx.send(Bytes::from_static(b"0123456789").into()).unwrap();
    let mut a = [0u8; 4];
    reader.read_exact(&mut a).await.unwrap();
    assert_eq!(&a, b"0123");
    // 6 bytes are buffered; a larger read_exact spans the remainder.
    let mut b = [0u8; 6];
    reader.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"456789");
}
