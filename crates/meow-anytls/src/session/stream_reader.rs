//! StreamReader - 独立的流读取器
//!
//! 负责从 Session 接收数据并提供给上层读取
//! 与 Stream 的写入操作完全分离

use crate::session::session::PendingBytes;
use std::io;
use tokio::sync::mpsc;

/// StreamReader 管理单个流的读取状态
///
/// 设计要点：
/// 1. reader_rx 和 reader_buffer 在同一个结构内，无需额外的锁
/// 2. 外部通过 &mut self 访问，保证互斥
/// 3. 不持有 Stream 的引用，完全独立
pub struct StreamReader {
    /// 流 ID（用于日志）
    id: u32,

    /// 从 Session 接收数据的 channel
    /// 注意：recv() 是 async 方法，需要 &mut self
    reader_rx: mpsc::UnboundedReceiver<PendingBytes>,

    /// 缓冲不完整的数据 — the unread remainder of the last `Bytes`
    /// chunk, kept as the chunk itself plus a read offset. Compared to
    /// the old `Vec<u8>` this is zero-copy on deposit (the remainder
    /// shares the channel item's allocation instead of
    /// `extend_from_slice` copying it) and O(1) per read (an offset bump
    /// instead of a `drain(..n)` memmove).
    reader_buffer: Option<(PendingBytes, usize)>,

    /// EOF 标志
    eof: bool,
}

impl StreamReader {
    /// 创建新的 StreamReader
    pub fn new(id: u32, reader_rx: mpsc::UnboundedReceiver<PendingBytes>) -> Self {
        Self {
            id,
            reader_rx,
            reader_buffer: None,
            eof: false,
        }
    }

    /// Bytes still unread in the buffered remainder.
    fn buffered_len(&self) -> usize {
        self.reader_buffer
            .as_ref()
            .map_or(0, |(b, off)| b.len() - off)
    }

    /// Copy out of the buffered remainder, advancing its offset and
    /// releasing the `Bytes` once fully consumed.
    fn read_buffered(&mut self, buf: &mut [u8]) -> usize {
        let Some((b, off)) = self.reader_buffer.as_mut() else {
            return 0;
        };
        let avail = b.len() - *off;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&b[*off..*off + n]);
        *off += n;
        let consumed = *off == b.len();
        if consumed {
            self.reader_buffer = None;
        }
        n
    }

    /// 读取数据到 buffer
    ///
    /// 实现逻辑：
    /// 1. 优先从 reader_buffer 读取
    /// 2. buffer 为空时从 channel 接收
    /// 3. 处理 EOF 情况
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // 1. 先检查 EOF
        if self.eof && self.buffered_len() == 0 {
            return Ok(0);
        }

        // 2. 从 buffer 读取（如果有数据）
        if self.buffered_len() > 0 {
            return Ok(self.read_buffered(buf));
        }

        // 3. buffer 为空，从 channel 接收新数据
        match self.reader_rx.recv().await {
            Some(data) => {
                // 直接填充到 buf
                let n = std::cmp::min(data.len(), buf.len());
                buf[..n].copy_from_slice(&data[..n]);

                // 剩余数据放入 buffer — the same `Bytes` allocation at
                // offset `n`; no copy.
                if n < data.len() {
                    self.reader_buffer = Some((data, n));
                }

                Ok(n)
            }
            None => {
                // Channel 关闭，表示 EOF
                tracing::debug!(
                    "[StreamReader] Channel closed (EOF) for stream_id={}",
                    self.id
                );
                self.eof = true;
                Ok(0)
            }
        }
    }

    /// 获取流 ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// 检查是否到达 EOF
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// 获取缓冲区大小（用于诊断）
    pub fn buffer_len(&self) -> usize {
        self.buffered_len()
    }

    /// 精确读取指定数量的字节（辅助方法）
    ///
    /// 类似于 AsyncReadExt::read_exact，但使用我们自己的 read() 方法
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        let total = buf.len();

        while offset < total {
            let n = self.read(&mut buf[offset..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("Failed to read exact {} bytes, only read {}", total, offset),
                ));
            }
            offset += n;
        }

        Ok(())
    }
}

// StreamReader 不需要实现 Clone
// 因为它包含 UnboundedReceiver（不可 Clone）

/// `AsyncRead` over the same state machine as [`read`](Self::read) —
/// lets shared parsers (`uot` address headers) drive the reader
/// generically alongside `tokio::io::ReadHalf`.
impl tokio::io::AsyncRead for StreamReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;

        if self.eof && self.buffered_len() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.buffered_len() > 0 {
            let take = buf.remaining().min(self.buffered_len());
            let dst = buf.initialize_unfilled_to(take);
            let n = self.read_buffered(dst);
            // `read_buffered` wrote `n` bytes into the initialised
            // prefix of `dst`.
            buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        match self.reader_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.reader_buffer = Some((data, n));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_stream_reader_basic() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut reader = StreamReader::new(1, rx);

        // 发送数据
        tx.send(Bytes::from("hello").into()).unwrap();

        // 读取数据
        let mut buf = vec![0u8; 10];
        let n = reader.read(&mut buf).await.unwrap();

        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn test_stream_reader_buffering() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut reader = StreamReader::new(1, rx);

        // 发送较大的数据
        tx.send(Bytes::from("hello world").into()).unwrap();

        // 分两次读取
        let mut buf = vec![0u8; 5];

        let n1 = reader.read(&mut buf).await.unwrap();
        assert_eq!(n1, 5);
        assert_eq!(&buf[..n1], b"hello");

        let n2 = reader.read(&mut buf).await.unwrap();
        assert_eq!(n2, 5);
        assert_eq!(&buf[..n2], b" worl");

        let n3 = reader.read(&mut buf).await.unwrap();
        assert_eq!(n3, 1);
        assert_eq!(&buf[..n3], b"d");
    }

    #[tokio::test]
    async fn test_stream_reader_eof() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut reader = StreamReader::new(1, rx);

        // 关闭 channel
        drop(tx);

        // 读取应该返回 0（EOF）
        let mut buf = vec![0u8; 10];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
        assert!(reader.is_eof());
    }

    /// B4: the leftover keeps the channel item's allocation — the
    /// remainder shares the sent `Bytes`' storage (no `extend_from_slice`
    /// copy), reads advance an offset, and `buffer_len` tracks it.
    #[tokio::test]
    async fn leftover_rides_the_channel_bytes_allocation() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut reader = StreamReader::new(1, rx);

        let sent = Bytes::from(vec![0xEEu8; 1024]);
        let sent_ptr = sent.as_ptr();
        tx.send(sent.into()).unwrap();

        // Read less than the chunk — the rest must stay in the SAME
        // allocation the channel delivered.
        let mut buf = vec![0u8; 100];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 100);
        assert_eq!(reader.buffer_len(), 924);
        let (leftover, off) = reader.reader_buffer.as_ref().expect("leftover buffered");
        assert_eq!(*off, 100);
        assert_eq!(
            leftover.as_ptr(),
            sent_ptr,
            "leftover shares the allocation"
        );

        // Draining the leftover returns the same bytes and releases it.
        let mut rest = vec![0u8; 1024];
        let mut got = 0;
        while reader.buffer_len() > 0 {
            got += reader.read(&mut rest[got..]).await.unwrap();
        }
        assert_eq!(got, 924);
        assert!(rest[..got].iter().all(|b| *b == 0xEE));
        assert!(reader.reader_buffer.is_none());
    }

    /// B4: EOF + leftover interplay — reads after the channel closes
    /// must still drain the buffered remainder before reporting EOF,
    /// and `read` returns 0 only once both are empty.
    #[tokio::test]
    async fn eof_drains_leftover_before_zero() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut reader = StreamReader::new(1, rx);
        tx.send(Bytes::from_static(b"abcdef").into()).unwrap();
        drop(tx);

        let mut buf = vec![0u8; 2];
        assert_eq!(reader.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"ab");
        // Channel is closed but the leftover must still be served.
        assert_eq!(reader.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"cd");
        assert_eq!(reader.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"ef");
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
        assert!(reader.is_eof());
    }

    #[tokio::test]
    async fn test_stream_reader_multiple_chunks() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut reader = StreamReader::new(1, rx);

        // 发送多个数据块
        tx.send(Bytes::from("chunk1").into()).unwrap();
        tx.send(Bytes::from("chunk2").into()).unwrap();
        tx.send(Bytes::from("chunk3").into()).unwrap();

        // 关闭 channel 以触发 EOF
        drop(tx);

        let mut buf = vec![0u8; 100];
        let mut total = Vec::new();

        // 读取所有数据
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total.extend_from_slice(&buf[..n]);
        }

        assert_eq!(total, b"chunk1chunk2chunk3");
    }
}
