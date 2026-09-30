//! [`BoringTlsStream`] — the stream [`TlsLayer`](super::TlsLayer) hands out
//! on the BoringSSL path, with XTLS-Vision's one-way switches to the raw
//! transport underneath ([`crate::enable_raw_read_passthrough`] /
//! [`crate::enable_raw_write_passthrough`]).
//!
//! Until a switch is enabled every call forwards to the `SslStream`
//! unchanged.  Switching mid-stream is sound because of two BoringSSL
//! properties, both checked against the vendored boring-sys 5.2 sources:
//!
//! * **No TLS read-ahead.**  `tls_open_record` reports a partial record as
//!   "need exactly 5 header bytes", then "need exactly this record's body",
//!   and `tls_read_buffer_extend_to` asks the BIO for no more than that
//!   (`SSL_CTX_set_read_ahead` is a no-op; `ssl.h`: "In TLS, BoringSSL
//!   does not implement read-ahead").
//!   `SSL_read` also returns plaintext from one record at most, and only
//!   opens a new record once the previous one is drained.  So once the
//!   caller has consumed the peer's last TLS record, every byte after it
//!   is still in the transport.  Plaintext BoringSSL decrypted but the
//!   caller has not read yet (`SSL_pending`) is drained before raw reads.
//! * **Writes are flushed before they are reported.**  `do_tls_write`
//!   returns success only after `ssl_write_buffer_flush` has handed the
//!   whole sealed record to the BIO; on a short BIO write it keeps the
//!   record pending and `SSL_write` fails with `WANT_WRITE`.  So after a
//!   completed `poll_write` no TLS byte is left to be ordered after raw
//!   ones.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use foreign_types::ForeignTypeRef;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::Stream;

pub(crate) struct BoringTlsStream {
    tls: tokio_boring::SslStream<Box<dyn Stream>>,
    raw_read: bool,
    raw_write: bool,
    /// The last TLS `poll_write` returned `Pending`: BoringSSL still holds
    /// a sealed record that must reach the transport before any raw byte.
    tls_write_pending: bool,
}

impl BoringTlsStream {
    pub(super) fn new(tls: tokio_boring::SslStream<Box<dyn Stream>>) -> Self {
        Self {
            tls,
            raw_read: false,
            raw_write: false,
            tls_write_pending: false,
        }
    }

    /// Read from the transport under TLS from now on, after any plaintext
    /// left over from the current record.  Refuses (returns `false`,
    /// staying on TLS) if BoringSSL has already buffered bytes past that
    /// record — only possible if the caller read beyond the peer's switch
    /// point, and those bytes could not be handed back.
    pub(crate) fn enable_raw_read_passthrough(&mut self) -> bool {
        let ssl = self.tls.ssl();
        // SAFETY: `ssl` is the live `SSL` owned by `self.tls`;
        // `SSL_has_pending` only reads its buffer lengths.
        let stranded =
            ssl.pending() == 0 && unsafe { boring_sys::SSL_has_pending(ssl.as_ptr()) } != 0;
        if stranded {
            tracing::warn!("BoringSSL raw read switch refused: ciphertext already buffered");
            return false;
        }
        self.raw_read = true;
        tracing::debug!("BoringSSL TLS raw read passthrough enabled");
        true
    }

    /// Write to the transport under TLS from now on.  Refuses (returns
    /// `false`) while a TLS write is still pending inside BoringSSL.
    pub(crate) fn enable_raw_write_passthrough(&mut self) -> bool {
        if self.tls_write_pending {
            tracing::warn!("BoringSSL raw write switch refused: a TLS record is still pending");
            return false;
        }
        self.raw_write = true;
        tracing::debug!("BoringSSL TLS raw write passthrough enabled");
        true
    }
}

impl AsyncRead for BoringTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // With plaintext pending, `SSL_read` serves it without touching the
        // transport; with none, it would pull the next record header —
        // which, once switched, is the peer's raw data.
        if this.raw_read && this.tls.ssl().pending() == 0 {
            return Pin::new(this.tls.get_mut()).poll_read(cx, buf);
        }
        Pin::new(&mut this.tls).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoringTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.raw_write {
            return Pin::new(this.tls.get_mut()).poll_write(cx, buf);
        }
        let res = Pin::new(&mut this.tls).poll_write(cx, buf);
        this.tls_write_pending = res.is_pending();
        res
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.raw_write {
            return Pin::new(this.tls.get_mut()).poll_write_vectored(cx, bufs);
        }
        // `SslStream` has no vectored path: seal the first non-empty
        // slice, exactly like tokio's default `poll_write_vectored`.
        let buf = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &**b);
        Pin::new(this).poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        self.raw_write && self.tls.get_ref().is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.raw_write {
            return Pin::new(this.tls.get_mut()).poll_flush(cx);
        }
        Pin::new(&mut this.tls).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // The peer now reads this direction raw: a close_notify record
        // would land in its plaintext, so close the transport directly.
        if this.raw_write {
            return Pin::new(this.tls.get_mut()).poll_shutdown(cx);
        }
        Pin::new(&mut this.tls).poll_shutdown(cx)
    }
}
