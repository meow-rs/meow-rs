//! Post-handshake data path for jls — a plain TLS 1.3 record stream.
//!
//! After the handshake the connection is ordinary TLS application data:
//! records sealed/opened with the application traffic keys derived in
//! `drive_tls13`. Unlike restls there is no tagging, masking, or script —
//! authentication lives entirely in the hello randoms. Post-handshake
//! handshake records are processed for `KeyUpdate` (key rotation, RFC 8446
//! §4.6.3) and otherwise skipped; `close_notify` maps to clean EOF.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::record_io::{poll_drain_outbox, serve_pending, RecordAssembler, RECORD_HDR};
use crate::restls::tls13::{pop_handshake_message, CipherSuite, RecordKey, HS_KEY_UPDATE};
use crate::restls::wire::{
    TLS_RECORD_ALERT, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC,
    TLS_RECORD_HANDSHAKE,
};
use crate::{Result, Stream, TransportError};

/// TLS plaintext record cap.
const MAX_PLAINTEXT: usize = 16384;
/// Inbound ciphertext record cap (TLS 1.3: 16384 + 256 expansion).
const MAX_RECORD: usize = 16640;
/// Bounded staging for sealed records not yet flushed to the socket.
const OUTBOX_CAP: usize = 256 * 1024;
/// Post-handshake message reassembly cap — upstream's `maxHandshake`
/// bounds the declared body at 64 KiB; the buffer also carries the
/// 4-byte message header (same bound as restls's `MAX_COVER_HS_BUF`).
const MAX_POST_HANDSHAKE_BUF: usize = 64 * 1024 + 4;
/// Non-advancing records tolerated before the connection dies — the
/// restls/upstream `maxUselessRecords` bound (32): stray CCS, empty
/// appdata, and consumed post-handshake messages all count, so a peer
/// streaming noise cannot livelock `poll_read` inside one poll.
const MAX_USELESS_RECORDS: u8 = 32;

/// Post-handshake jls stream — a real TLS 1.3 connection driven by the
/// record-level client.
pub(crate) struct JlsStream<S> {
    inner: S,
    /// Application traffic keys — each `RecordKey` retains its secret, so
    /// `traffic upd` rotation is `rekey()` (RFC 8446 §4.6.3).
    read_key: RecordKey,
    write_key: RecordKey,
    /// Reassembly buffer for post-handshake handshake messages.
    hs_buf: VecDeque<u8>,
    /// Inbound record assembly.
    asm: RecordAssembler,
    /// Decrypted application data waiting for `poll_read` callers.
    inbox: VecDeque<u8>,
    /// Sealed records waiting for socket capacity.
    outbox: VecDeque<u8>,
    /// Peer sent close_notify (or an equivalent clean end).
    eof: bool,
    sent_close_notify: bool,
    /// Consecutive records that produced no application data.
    useless_records: u8,
}

impl<S> JlsStream<S> {
    pub(crate) fn new(
        inner: S,
        cipher: CipherSuite,
        client_secret: &[u8],
        server_secret: &[u8],
        leftover_handshake: &[u8],
    ) -> Result<Self> {
        let mut s = Self {
            read_key: RecordKey::new(cipher, server_secret),
            write_key: RecordKey::new(cipher, client_secret),
            inner,
            hs_buf: VecDeque::new(),
            asm: RecordAssembler::new(),
            inbox: VecDeque::new(),
            outbox: VecDeque::new(),
            eof: false,
            sent_close_notify: false,
            useless_records: 0,
        };
        // Post-Finished messages coalesced into the Finished record (or a
        // partial tail of one) continue the post-handshake stream — a
        // dropped KeyUpdate would desync the epoch.
        s.handle_inner(TLS_RECORD_HANDSHAKE, leftover_handshake)?;
        Ok(s)
    }

    /// Seal `plaintext` into `outbox` as ≤16 KiB application-data records.
    fn seal_appdata(&mut self, mut plaintext: &[u8]) -> Result<()> {
        while !plaintext.is_empty() {
            let chunk = plaintext.len().min(MAX_PLAINTEXT);
            let record = self
                .write_key
                .seal(TLS_RECORD_APPLICATION_DATA, &plaintext[..chunk])?;
            self.outbox.extend(record);
            plaintext = &plaintext[chunk..];
        }
        Ok(())
    }

    /// One more record consumed without producing data — kills the
    /// connection past the `maxUselessRecords` bound. Saturating:
    /// `poll_read` is not fused, so a post-error re-poll must not wrap.
    fn tick_useless(&mut self) -> io::Result<()> {
        self.useless_records = self.useless_records.saturating_add(1);
        if self.useless_records > MAX_USELESS_RECORDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "jls: too many useless records",
            ));
        }
        Ok(())
    }

    /// Handle one decrypted post-handshake record body; returns the
    /// number of handshake messages consumed (0 for alerts — the caller
    /// maps errors to io).
    fn handle_inner(&mut self, typ: u8, body: &[u8]) -> Result<usize> {
        match typ {
            TLS_RECORD_HANDSHAKE => {
                self.hs_buf.extend(body);
                if self.hs_buf.len() > MAX_POST_HANDSHAKE_BUF {
                    return Err(TransportError::Tls(
                        "jls: post-handshake buffer overflow".into(),
                    ));
                }
                let mut consumed = 0usize;
                while let Some(msg) = pop_handshake_message(&mut self.hs_buf) {
                    consumed += 1;
                    if msg.typ != HS_KEY_UPDATE {
                        // NewSessionTicket and friends carry no state we
                        // use; a post-handshake CertificateRequest would be
                        // answered with an empty Certificate by a real
                        // stack, but a jls cover never sends one.
                        continue;
                    }
                    match msg.body.as_slice() {
                        // update_not_requested — rotate the read epoch.
                        [0] => self.read_key.rekey(),
                        // update_requested — rotate the read epoch, answer
                        // KeyUpdate(0) under the *current* write key, then
                        // rotate the write epoch (RFC 8446 §4.6.3).
                        [1] => {
                            self.read_key.rekey();
                            if let Some(sealed) = self.write_key.seal_key_update_response() {
                                self.outbox.extend(sealed);
                            }
                        }
                        _ => {
                            return Err(TransportError::Tls(format!(
                                "jls: malformed KeyUpdate body {:?}",
                                msg.body
                            )))
                        }
                    }
                }
                Ok(consumed)
            }
            // close_notify (any level, description 0) is a clean EOF;
            // other alerts fatal.
            TLS_RECORD_ALERT if body.len() == 2 && body[1] == 0 => {
                self.eof = true;
                Ok(0)
            }
            TLS_RECORD_ALERT => Err(TransportError::Tls(format!("jls: TLS alert: {body:?}"))),
            other => Err(TransportError::Tls(format!(
                "jls: unexpected inner record type {other}"
            ))),
        }
    }
}

impl<S> AsyncRead for JlsStream<S>
where
    S: Stream,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Keep staged KeyUpdate responses moving.
        if let Poll::Ready(Err(e)) = poll_drain_outbox(&mut this.inner, &mut this.outbox, cx, "jls")
        {
            return Poll::Ready(Err(e));
        }
        loop {
            if !this.inbox.is_empty() {
                serve_pending(&mut this.inbox, buf);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.asm.poll_fill(
                &mut this.inner,
                cx,
                None,
                true,
                &mut |hdr| {
                    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    if len > MAX_RECORD {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "jls: record too large",
                        ));
                    }
                    Ok(())
                },
                "jls",
            ) {
                Poll::Pending => {
                    // A KeyUpdate may have staged a response mid-fill —
                    // push it out (arming the write waker) before parking
                    // on the read side, or an idle peer deadlocks us.
                    match poll_drain_outbox(&mut this.inner, &mut this.outbox, cx, "jls") {
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        _ => return Poll::Pending,
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(None)) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(()))) => {}
            }
            // Stray CCS records are legal post-handshake — tolerated,
            // bounded like every other non-advancing record.
            if this.asm.rec.first() == Some(&TLS_RECORD_CHANGE_CIPHER_SPEC) {
                if let Err(e) = this.tick_useless() {
                    return Poll::Ready(Err(e));
                }
                continue;
            }
            let mut header = [0u8; RECORD_HDR];
            header.copy_from_slice(&this.asm.rec[..RECORD_HDR]);
            let (typ, body) = match this.read_key.open(&header, &this.asm.rec[RECORD_HDR..]) {
                Ok(v) => v,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
            };
            if typ == TLS_RECORD_APPLICATION_DATA {
                // Empty appdata (TLS 1.3 padding) produces nothing —
                // count it instead of resetting the streak.
                if body.is_empty() {
                    if let Err(e) = this.tick_useless() {
                        return Poll::Ready(Err(e));
                    }
                    continue;
                }
                this.useless_records = 0;
                this.inbox.extend(&body[..]);
                continue;
            }
            let consumed = match this.handle_inner(typ, &body) {
                Ok(n) => n,
                Err(e) => {
                    let kind = if typ == TLS_RECORD_ALERT {
                        io::ErrorKind::ConnectionAborted
                    } else {
                        io::ErrorKind::InvalidData
                    };
                    return Poll::Ready(Err(io::Error::new(kind, e.to_string())));
                }
            };
            if consumed > 0 {
                // Post-handshake handshake messages do NOT reset the
                // streak — upstream `handlePostHandshakeMessage` ticks
                // `retryCount` once per consumed message, so a peer
                // streaming one-message records still dies at the cap.
                let n = consumed.min(u8::MAX as usize) as u8;
                this.useless_records = this.useless_records.saturating_add(n);
                if this.useless_records > MAX_USELESS_RECORDS {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "jls: too many useless records",
                    )));
                }
            }
            // KeyUpdate responses stage into `outbox` during processing —
            // push them now (a Pending drain still parks the read on the
            // write waker below instead of spinning on the socket).
            if let Poll::Ready(Err(e)) =
                poll_drain_outbox(&mut this.inner, &mut this.outbox, cx, "jls")
            {
                return Poll::Ready(Err(e));
            }
        }
    }
}

impl<S> AsyncWrite for JlsStream<S>
where
    S: Stream,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // A real TLS stack errors on write after close_notify — appdata
        // must never trail the alert on the wire.
        if this.sent_close_notify {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "jls: write after close_notify",
            )));
        }
        if this.outbox.len() > OUTBOX_CAP {
            match poll_drain_outbox(&mut this.inner, &mut this.outbox, cx, "jls") {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if let Err(e) = this.seal_appdata(buf) {
            return Poll::Ready(Err(io::Error::other(e.to_string())));
        }
        // Once sealed the bytes are consumed — reporting `Pending` would
        // re-seal them under bumped record sequence numbers.
        if let Poll::Ready(Err(e)) = poll_drain_outbox(&mut this.inner, &mut this.outbox, cx, "jls")
        {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match poll_drain_outbox(&mut this.inner, &mut this.outbox, cx, "jls") {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // A real TLS client emits close_notify through the record cipher —
        // a clean shutdown, not an abrupt TCP close.
        if !this.sent_close_notify {
            this.sent_close_notify = true;
            if let Ok(sealed) = this.write_key.seal(TLS_RECORD_ALERT, &[1, 0]) {
                this.outbox.extend(sealed);
            }
        }
        match poll_drain_outbox(&mut this.inner, &mut this.outbox, cx, "jls") {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
