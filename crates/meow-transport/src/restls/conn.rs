//! Post-handshake restls stream — tagged `application_data` records shaped by
//! the record script. A port of the `restlsAuthed` halves of
//! `readRecordOrCCS` and `writeRestlsApplicationRecord` plus
//! `handleRestlsCommand` from `restls-client-go` (`conn.go`).
//!
//! Semantics preserved from upstream:
//!
//! * every inbound record ticks `to_client_ctr` — tagged records *and* real
//!   cover records (session tickets) that fail tag verification and fall back
//!   to the negotiated cipher;
//! * an inbound record carrying `Respond(n)` asks for `n` fake all-padding
//!   records; one of them is absorbed by a data write that was in flight;
//! * a script line with `<` marks the record as interrupting — subsequent
//!   writes are held in `send_buf` until the next inbound tagged record;
//! * the sealed client-Finished record is mixed into the first tagged
//!   record's MAC (TLS 1.3 and resumed TLS 1.2; see `client_finished`).
//!
//! When the cover handshake never showed the server-auth mask (the "restls
//! server" was a plain relay), upstream degrades to transparent TLS to the
//! cover host; `Mode::Transparent` keeps that behaviour.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::record_io::{poll_drain_outbox, serve_pending, RecordAssembler};
use crate::restls::script::{act_according_to_script, Command, Line};
use crate::restls::wire::{
    self, AUTH_HEADER_LEN, GCM_NONCE_LEN, RECORD_HDR, TLS_RECORD_ALERT,
    TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};

/// Cap on `send_buf` while writes are blocked behind a script interrupt —
/// upstream accepts unboundedly; backpressure applies past this point.
const SEND_BUF_CAP: usize = 256 * 1024;

/// Cap on encoded records staged in `outbox`.
const OUTBOX_CAP: usize = 256 * 1024;

/// Non-advancing records tolerated before the connection dies —
/// upstream's `maxUselessRecords` (32; it counts every record that
/// produces no data: stray CCS, consumed handshake records, empty
/// appdata, tolerated alerts). Legal noise stays bounded instead of
/// spinning the read loop forever.
const MAX_USELESS_RECORDS: u8 = 32;

/// Reassembly bound for post-handshake cover messages (KeyUpdate may
/// straddle records). NSTs ride the same buffer; the cap keeps a peer
/// from growing it with an unterminated message. Upstream's
/// `maxHandshake` bounds the declared *body* at 64 KiB — the buffer
/// also carries the 4-byte message header.
const MAX_COVER_HS_BUF: usize = 64 * 1024 + 4;

/// The negotiated cover cipher — kept after the handshake for stray real
/// records (session tickets) and, when the server never authenticated, for
/// transparent TLS passthrough.
pub(crate) trait CoverCipher: Send + Sync {
    /// Open one record; `record` includes the 5-byte header. Returns the
    /// inner content type and plaintext on success.
    fn open(&mut self, record: &mut [u8]) -> Option<(u8, Vec<u8>)>;
    /// Seal `body` as `application_data` record(s), fragmented at the TLS
    /// plaintext limit (`wire::MAX_PLAINTEXT`).
    fn seal(&mut self, body: &[u8]) -> Vec<u8>;
    /// Seal a close_notify alert record — upstream `Close` sends a real
    /// TLS alert through the cover cipher.
    fn seal_close_notify(&mut self) -> Vec<u8>;
    /// TLS 1.3 KeyUpdate received: derive the next traffic generation.
    /// No-op for TLS 1.2 (no post-handshake rekey).
    fn rekey(&mut self) {}
    /// Peer sent KeyUpdate with `request_update`: seal our
    /// `key_update_not_requested` response, then rekey. `None` for TLS 1.2.
    fn seal_key_update_response(&mut self) -> Option<Vec<u8>> {
        None
    }
}

/// Handshake output the data path consumes.
pub(crate) struct RestlsUpgraded<S> {
    pub(crate) inner: S,
    pub(crate) server_random: [u8; 32],
    /// Sealed client-Finished record — `Some` for TLS 1.3 and resumed 1.2.
    pub(crate) client_finished: Option<Vec<u8>>,
    /// Whether the server-auth mask decoded (restls server confirmed).
    pub(crate) authed: bool,
    /// Cover ciphers — `Some` iff the cover handshake completed.
    pub(crate) cover_read: Option<Box<dyn CoverCipher>>,
    pub(crate) cover_write: Option<Box<dyn CoverCipher>>,
    /// Whether the cover negotiated a TLS 1.2 GCM suite (`restls12WithGCM`).
    pub(crate) tls12_gcm: bool,
    /// `restls12GCMServerDisableCtr` — nonce counter check off.
    pub(crate) gcm_ctr_disabled: bool,
    /// Cover's next inbound record sequence (post-handshake). A seq-derived
    /// cover's explicit nonces continue the handshake's count — e.g. a
    /// NewSessionTicket-then-Finished flight means the first real cover
    /// record carries nonce 2. Upstream hardcodes a fresh counter, which is
    /// only correct when Finished was the sole post-CCS record.
    pub(crate) gcm_next_seq: u64,
    /// Plaintext handshake bytes coalesced past the server Finished — a
    /// same-record KeyUpdate or NST rides here (already decrypted, just
    /// unprocessed). Consumed by `RestlsStream::new`; dropping it would
    /// desync the cover cipher.
    pub(crate) cover_hs_pending: Vec<u8>,
}

/// What a decrypted cover record meant for the reader. Post-handshake
/// handshake records do NOT reset the streak — upstream resets
/// `retryCount` only on non-empty application data (or handshake data
/// while the handshake is still in progress), and ticks once per
/// consumed post-handshake message; everything else ticks per record.
enum CoverOutcome {
    /// Not a cover record at all.
    Rejected,
    /// Consumed `n` non-advancing units — added to the streak.
    Consumed(u8),
    /// `close_notify` — clean EOF, never counts toward the bound.
    Eof,
}

/// Post-handshake stream speaking the tagged restls record protocol.
pub(crate) struct RestlsStream<S> {
    inner: S,
    secret: [u8; 32],
    server_random: [u8; 32],
    script: Vec<Line>,
    /// `restlsAuthed` — false degrades to transparent cover-TLS passthrough.
    authed: bool,

    to_server_ctr: u64,
    to_client_ctr: u64,
    tls12_gcm: bool,
    gcm_ctr_disabled: bool,

    /// Sealed Finished for the first tagged record's MAC.
    client_finished: Option<Vec<u8>>,
    /// Real-cipher readers/writers for cover records.
    cover_read: Option<Box<dyn CoverCipher>>,
    cover_write: Option<Box<dyn CoverCipher>>,
    /// TLS 1.2-GCM nonce for the next real cover record — seeded from the
    /// handshake's consumed sequence (`RestlsUpgraded::gcm_next_seq`).
    gcm_read_seq: u64,
    /// close_notify already staged — `poll_shutdown` sends it once.
    sent_close_notify: bool,

    /// Application data held behind a script interrupt or mid-split.
    send_buf: VecDeque<u8>,
    /// Encoded records awaiting the socket (fake responses ride here too).
    outbox: VecDeque<u8>,
    /// `restlsWritePending` — a script `<` interrupt holds writes until the
    /// next inbound tagged record.
    write_pending: bool,

    /// Record reassembly.
    asm: RecordAssembler,
    /// Extracted application data awaiting `poll_read` consumers.
    inbox: VecDeque<u8>,
    /// Waker registered when `write_pending`/`send_buf` backpressure pends a
    /// write — woken when an inbound record releases the hold (split
    /// read/write tasks need this; `poll_read` runs on the other half).
    blocked_write_waker: Option<std::task::Waker>,
    /// Records consumed without producing data — CCS, cover handshake
    /// drops, empty appdata. Bounded by `MAX_USELESS_RECORDS`.
    useless_records: u8,
    /// Partial post-handshake cover message carried across records —
    /// upstream buffers these in `c.hand` the same way.
    cover_hs_buf: Vec<u8>,
    eof: bool,
}

fn rand_pad(buf: &mut [u8]) {
    rand::Rng::fill(&mut rand::rng(), buf);
}

impl<S> RestlsStream<S> {
    pub(crate) fn new(
        up: RestlsUpgraded<S>,
        secret: [u8; 32],
        script: Vec<Line>,
    ) -> io::Result<Self> {
        let mut s = Self {
            inner: up.inner,
            secret,
            server_random: up.server_random,
            script,
            authed: up.authed,
            to_server_ctr: 0,
            to_client_ctr: 0,
            tls12_gcm: up.tls12_gcm,
            gcm_ctr_disabled: up.gcm_ctr_disabled,
            client_finished: up.client_finished,
            cover_read: up.cover_read,
            cover_write: up.cover_write,
            gcm_read_seq: up.gcm_next_seq,
            sent_close_notify: false,
            send_buf: VecDeque::new(),
            outbox: VecDeque::new(),
            write_pending: false,
            asm: RecordAssembler::new(),
            inbox: VecDeque::new(),
            blocked_write_waker: None,
            useless_records: 0,
            cover_hs_buf: up.cover_hs_pending,
            eof: false,
        };
        // Handshake plaintext coalesced past the server Finished is
        // already decrypted — consume it now so a same-record KeyUpdate
        // rekeys before the next cover record opens.
        s.handle_cover_handshake(&[])?;
        Ok(s)
    }

    /// Write side: the client always emits the 8-byte nonce slot in TLS 1.2
    /// GCM mode — upstream `writeRestlsApplicationRecord` has no `disableCtr`
    /// check, and the restls server rejects client records without it.
    fn out_nonce_slot(&self) -> bool {
        self.tls12_gcm
    }

    /// Read side: the server drops the nonce slot when the cover's nonces
    /// aren't seq-derived — upstream `restls12GCMServerDisableCtr` /
    /// `!parrotGCM`. Inbound-only asymmetry.
    fn in_nonce_slot(&self) -> bool {
        self.tls12_gcm && !self.gcm_ctr_disabled
    }

    /// Inbound record-size cap — upstream `maxCiphertext`: 18432 for
    /// TLS 1.2, 16640 for TLS 1.3.
    fn max_record(&self) -> usize {
        if self.tls12_gcm {
            18432
        } else {
            16640
        }
    }

    /// Per-record auth overhead on the write side (MAC+mask, +GCM nonce).
    fn out_header_len(&self) -> usize {
        AUTH_HEADER_LEN
            + if self.out_nonce_slot() {
                GCM_NONCE_LEN
            } else {
                0
            }
    }

    /// Encode one record over `data` per the script and stage it in `outbox`.
    /// Returns the number of `data` bytes consumed.
    fn stage_record(&mut self, data: &[u8], fake: bool) -> (usize, Command) {
        let client_finished = self.client_finished.take();
        let (payload_len, data_len, padding_len, command) = act_according_to_script(
            data,
            self.to_server_ctr,
            &self.script,
            self.out_header_len(),
        );
        let spec = wire::TaggedRecord {
            counter: self.to_server_ctr,
            data,
            payload_len,
            data_len,
            padding_len,
            command,
            client_finished: client_finished.as_deref(),
            tls12_gcm: self.out_nonce_slot(),
        };
        // The Finished record binds into the *first* tagged record only.
        let record = wire::build_tagged_record(&self.secret, &self.server_random, &spec, rand_pad);
        self.outbox.extend(&record);
        self.to_server_ctr += 1;
        if command.need_interrupt() && !fake {
            self.write_pending = true;
        }
        (data_len, command)
    }

    /// Drain `outbox` into the socket.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        poll_drain_outbox(&mut self.inner, &mut self.outbox, cx, "restls")
    }

    /// Encode every `send_buf` byte into records (script-shaped).
    /// Returns whether at least one record was staged — the `Respond`
    /// handler counts a released data record as one of the requested
    /// fakes (upstream `handleRestlsCommand`'s `sent` decrement).
    fn flush_send_buf(&mut self) -> bool {
        let mut emitted = false;
        let header_len = self.out_header_len();
        let nonce_slot = self.out_nonce_slot();
        loop {
            let staged = {
                let data = self.send_buf.make_contiguous();
                if data.is_empty() {
                    break;
                }
                // Take only once data is known non-empty — an early `take()`
                // would drop the Finished binding on a zero-length flush.
                let client_finished = self.client_finished.take();
                let (payload_len, data_len, padding_len, command) =
                    act_according_to_script(data, self.to_server_ctr, &self.script, header_len);
                let spec = wire::TaggedRecord {
                    counter: self.to_server_ctr,
                    data,
                    payload_len,
                    data_len,
                    padding_len,
                    command,
                    client_finished: client_finished.as_deref(),
                    tls12_gcm: nonce_slot,
                };
                let record =
                    wire::build_tagged_record(&self.secret, &self.server_random, &spec, rand_pad);
                (data_len, command, record)
            };
            self.outbox.extend(&staged.2);
            self.to_server_ctr += 1;
            emitted = true;
            self.send_buf.drain(..staged.0);
            if staged.1.need_interrupt() {
                self.write_pending = true;
                break;
            }
            // A scripted zero-data record doesn't end the pass — the script
            // index advanced, so the next line may still emit data
            // (`for len(data) > 0` upstream). `payload_len` is never 0 here
            // since the auth header alone exceeds it.
        }
        emitted
    }

    /// Upstream `handleRestlsCommand`: an inbound `Respond(n)` produces `n`
    /// fake all-padding records — minus one when the same inbound record
    /// released `<`-held writes that actually emitted (`sent` decrement).
    fn handle_command(&mut self, command: Command, released: bool) {
        let Command::Respond(n) = command else {
            return;
        };
        let n = if released { n.saturating_sub(1) } else { n };
        for _ in 0..n {
            // Respond(≤255) × scripted sizes can stage ~4.5 MB per inbound
            // record — bound by the same cap writes respect. Dropped fakes
            // lose only traffic-shaping bytes; the data path is unaffected.
            if self.outbox.len() > OUTBOX_CAP {
                break;
            }
            // Upstream writes restlsRandomResponseMagic, which clears
            // write_pending and emits one scripted-size empty record.
            self.write_pending = false;
            self.stage_record(&[], true);
        }
    }

    /// Fallback for real cover records (post-handshake session tickets and
    /// alerts): decrypt through the negotiated cipher. Application data is
    /// dropped — upstream discards it (`data = nil`); alerts are fatal.
    /// One more record consumed without producing data — kills the
    /// connection past upstream's `maxUselessRecords` bound. Saturating:
    /// `poll_read` is not fused, so a post-error re-poll must not wrap.
    fn tick_useless(&mut self) -> io::Result<()> {
        self.useless_records = self.useless_records.saturating_add(1);
        if self.useless_records > MAX_USELESS_RECORDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "restls: too many useless records",
            ));
        }
        Ok(())
    }

    fn accept_cover_record(&mut self, record: &mut [u8]) -> io::Result<CoverOutcome> {
        let nonce_slot = self.in_nonce_slot();
        let Some(cover) = &mut self.cover_read else {
            return Ok(CoverOutcome::Rejected);
        };
        if nonce_slot {
            // Upstream rewrites the nonce field with the real-record counter
            // before decrypting — the tagged-protocol nonce and the cover's
            // explicit nonce share the slot.
            if record.len() < RECORD_HDR + GCM_NONCE_LEN {
                return Ok(CoverOutcome::Rejected);
            }
            record[RECORD_HDR..RECORD_HDR + GCM_NONCE_LEN]
                .copy_from_slice(&self.gcm_read_seq.to_be_bytes());
            self.gcm_read_seq += 1;
        }
        match cover.open(record) {
            Some((typ, plain)) => {
                if typ == TLS_RECORD_ALERT {
                    // close_notify ([level, 0]) is a clean EOF — upstream
                    // maps it to `io.EOF` regardless of the streak.
                    if plain.len() == 2 && plain[1] == 0 {
                        self.eof = true;
                        return Ok(CoverOutcome::Eof);
                    }
                    // TLS 1.2 permits warning alerts ([warning, desc]) —
                    // upstream retries them (bounded); TLS 1.3 alerts
                    // are always fatal.
                    if self.tls12_gcm && plain.len() == 2 && plain[0] == 1 {
                        return Ok(CoverOutcome::Consumed(1));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "restls: cover alert",
                    ));
                }
                if typ == wire::TLS_RECORD_HANDSHAKE {
                    // Post-handshake cover messages: session tickets are
                    // dropped (no resumption), but a KeyUpdate must rekey
                    // or every later cover record desyncs.
                    let n = self.handle_cover_handshake(&plain)?;
                    return Ok(CoverOutcome::Consumed(n.min(u8::MAX as usize) as u8));
                }
                // Other decrypted records (empty appdata, stray cover
                // data) advance nothing — one tick.
                Ok(CoverOutcome::Consumed(1))
            }
            None => Ok(CoverOutcome::Rejected),
        }
    }

    /// Walk post-handshake handshake messages; KeyUpdate (type 24) rekeys
    /// the inbound cipher, and `request_update` additionally queues our
    /// `key_update_not_requested` + outbound rekey. Other types (NST, …)
    /// are dropped — upstream's embedded stack would consume them, but we
    /// never resume so tickets carry nothing we need. Messages may
    /// straddle records; the leftover tail rides `cover_hs_buf` (bounded
    /// by `MAX_COVER_HS_BUF`) exactly like upstream's `c.hand` buffer.
    /// Returns the number of complete messages consumed.
    fn handle_cover_handshake(&mut self, hs: &[u8]) -> io::Result<usize> {
        const HS_KEY_UPDATE: u8 = 24;
        self.cover_hs_buf.extend_from_slice(hs);
        if self.cover_hs_buf.len() > MAX_COVER_HS_BUF {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "restls: oversized cover handshake message",
            ));
        }
        let mut buf = std::mem::take(&mut self.cover_hs_buf);
        let mut off = 0;
        let mut consumed = 0usize;
        while buf.len() - off >= 4 {
            let len = (u32::from(buf[off + 1]) << 16
                | u32::from(buf[off + 2]) << 8
                | u32::from(buf[off + 3])) as usize;
            if buf.len() - off < 4 + len {
                break;
            }
            let msg = &buf[off..off + 4 + len];
            // A post-handshake HelloRequest (TLS 1.2 renegotiation)
            // can't be answered — upstream alerts `no_renegotiation`
            // and the server aborts; erroring is the same outcome
            // without pretending the stall is progress.
            if msg[0] == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "restls: cover renegotiation unsupported",
                ));
            }
            if msg[0] == HS_KEY_UPDATE && len >= 1 {
                if let Some(read) = &mut self.cover_read {
                    read.rekey();
                }
                if msg[4] == 1 {
                    if let Some(write) = &mut self.cover_write {
                        if let Some(record) = write.seal_key_update_response() {
                            self.outbox.extend(&record);
                        }
                    }
                }
            }
            consumed += 1;
            off += 4 + len;
        }
        self.cover_hs_buf = buf.split_off(off);
        Ok(consumed)
    }

    /// Process one complete inbound record (tagged or cover). Fills `inbox`.
    fn process_record(&mut self, mut record: Vec<u8>) -> io::Result<()> {
        if record.first() == Some(&TLS_RECORD_ALERT) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "restls: alert record",
            ));
        }
        if record.first() == Some(&TLS_RECORD_CHANGE_CIPHER_SPEC) {
            // Stray post-handshake CCS: upstream's `readRecordOrCCS`
            // consumes CCS in a separate arm before the tagged path, so
            // neither counter ticks — drop it the same way, bounded by
            // the shared useless-record cap.
            self.tick_useless()?;
            return Ok(());
        }
        let tagged = wire::extract_tagged_record(
            &record,
            &self.secret,
            &self.server_random,
            self.to_client_ctr,
            self.tls12_gcm,
            self.gcm_ctr_disabled,
        );
        match tagged {
            Ok(decoded) => {
                self.inbox.extend(
                    record[decoded.payload_start..decoded.payload_start + decoded.data_len]
                        .iter()
                        .copied(),
                );
                self.to_client_ctr += 1;
                // A record carrying no data (fakes, `Respond` replies)
                // advances nothing — upstream ticks `retryCount`; only
                // real payload resets the streak.
                if decoded.data_len == 0 {
                    self.tick_useless()?;
                } else {
                    self.useless_records = 0;
                }
                // A clean inbound record unblocks `<`-held writes.
                let mut released = false;
                if self.write_pending {
                    self.write_pending = false;
                    released = self.flush_send_buf();
                    if let Some(w) = self.blocked_write_waker.take() {
                        w.wake();
                    }
                }
                self.handle_command(decoded.command, released);
                Ok(())
            }
            Err(_) => match self.accept_cover_record(&mut record) {
                // Decrypted but non-advancing — upstream ticks
                // `retryCount` once per consumed handshake message,
                // once per other record kind.
                Ok(CoverOutcome::Consumed(n)) => {
                    self.to_client_ctr += 1;
                    self.useless_records = self.useless_records.saturating_add(n);
                    if self.useless_records > MAX_USELESS_RECORDS {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "restls: too many useless records",
                        ));
                    }
                    Ok(())
                }
                // close_notify surfaces a clean EOF even at the streak
                // boundary — upstream returns `io.EOF` unconditionally.
                Ok(CoverOutcome::Eof) => {
                    self.to_client_ctr += 1;
                    Ok(())
                }
                Ok(CoverOutcome::Rejected) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "restls: record failed authentication",
                )),
                Err(e) => Err(e),
            },
        }
    }
}

impl<S> AsyncRead for RestlsStream<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Keep staged output moving so `<`-paced scripts and fake responses
        // don't stall behind an idle writer.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        if !this.inbox.is_empty() {
            serve_pending(&mut this.inbox, buf);
            return Poll::Ready(Ok(()));
        }
        if this.eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            // Assemble the next complete record; the header gate bounds
            // the declared length before any payload is read.
            let max_record = this.max_record();
            let ready = this.asm.poll_fill(
                &mut this.inner,
                cx,
                None,
                true,
                &mut |hdr| {
                    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    if len > max_record {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "restls: record too large",
                        ))
                    } else {
                        Ok(())
                    }
                },
                "restls",
            );
            match ready {
                Poll::Ready(Ok(None)) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Records processed so far may have staged
                    // `Respond` fakes or released `<`-held writes —
                    // push them out before parking.
                    if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                        return Poll::Ready(Err(e));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Ok(Some(()))) => {}
            }
            let mut record = std::mem::take(&mut this.asm.rec);

            // Transparent mode: records go through the cover cipher.
            if !this.authed {
                // Stray CCS records are legal post-handshake (TLS 1.3
                // middlebox-compat) — skip them, matching the authed path,
                // bounded by the same streak cap.
                if record.first() == Some(&TLS_RECORD_CHANGE_CIPHER_SPEC) {
                    if let Err(e) = this.tick_useless() {
                        return Poll::Ready(Err(e));
                    }
                    continue;
                }
                match this.cover_read.as_mut().and_then(|c| c.open(&mut record)) {
                    Some((typ, plain)) if typ == TLS_RECORD_APPLICATION_DATA => {
                        // Empty appdata (TLS 1.3 padding, CBC IV
                        // randomization) produces nothing — returning an
                        // unfilled Ready would read as EOF upstream-style
                        // useless records just retry (bounded).
                        if plain.is_empty() {
                            if let Err(e) = this.tick_useless() {
                                return Poll::Ready(Err(e));
                            }
                            continue;
                        }
                        this.useless_records = 0;
                        this.inbox.extend(&plain[..]);
                        serve_pending(&mut this.inbox, buf);
                        return Poll::Ready(Ok(()));
                    }
                    // Post-handshake handshake records are consumed
                    // internally by a real TLS stack — a fallback conn
                    // must still honor KeyUpdate or the next cover record
                    // desyncs; NSTs are dropped (no resumption).
                    Some((typ, plain)) if typ == TLS_RECORD_HANDSHAKE => {
                        let n = match this.handle_cover_handshake(&plain) {
                            Ok(n) => n.min(u8::MAX as usize) as u8,
                            Err(e) => return Poll::Ready(Err(e)),
                        };
                        // Post-handshake handshake records do NOT reset
                        // the streak — upstream ticks `retryCount` once
                        // per consumed message, so a one-message-per-
                        // record feed still dies at the cap.
                        this.useless_records = this.useless_records.saturating_add(n);
                        if this.useless_records > MAX_USELESS_RECORDS {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "restls: too many useless records",
                            )));
                        }
                        continue;
                    }
                    // close_notify ([level, 0]) is a clean EOF. TLS 1.2
                    // warning alerts ([warning, desc]) are tolerated —
                    // upstream retries them (bounded); TLS 1.3 alerts
                    // are always fatal.
                    Some((typ, plain)) if typ == TLS_RECORD_ALERT => {
                        if plain.len() == 2 && plain[1] == 0 {
                            this.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        if this.tls12_gcm && plain.len() == 2 && plain[0] == 1 {
                            if let Err(e) = this.tick_useless() {
                                return Poll::Ready(Err(e));
                            }
                            continue;
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "restls: cover alert",
                        )));
                    }
                    Some((typ, _)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("restls: cover record type {typ}"),
                        )));
                    }
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "restls: bad cover record",
                        )));
                    }
                }
            }

            if let Err(e) = this.process_record(record) {
                return Poll::Ready(Err(e));
            }
            // Upstream emits `Respond` fakes and released `<`-held writes
            // synchronously during the read — drain them now rather than
            // stalling them behind the next poll. A Pending drain still
            // returns staged data; the socket's writability wakes us.
            if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
            if !this.inbox.is_empty() {
                serve_pending(&mut this.inbox, buf);
                return Poll::Ready(Ok(()));
            }
            // A cover close_notify lands via `process_record` — surface
            // the EOF now (upstream's sticky `io.EOF`) instead of
            // parking in `poll_fill` for a record that never comes.
            if this.eof {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S> AsyncWrite for RestlsStream<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.authed {
            // Transparent cover-TLS passthrough.
            if self.outbox.len() > OUTBOX_CAP && matches!(self.poll_drain(cx), Poll::Pending) {
                return Poll::Pending;
            }
            let Some(cover) = &mut self.cover_write else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "restls: no cover cipher",
                )));
            };
            let record = cover.seal(buf);
            if record.is_empty() && !buf.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "restls: cover seal failed",
                )));
            }
            self.outbox.extend(&record);
            // Once sealed the bytes are consumed — reporting `Pending` here
            // would make a retry seal the same `buf` again (duplicate data
            // under bumped record sequence numbers).
            if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        // Held behind a `<` interrupt: buffer (bounded), matching upstream's
        // sendBuf accept-and-wait.  Register the waker — a split
        // read-half task is what clears `write_pending`.
        if self.write_pending {
            if !buf.is_empty() && self.send_buf.len() + buf.len() > SEND_BUF_CAP {
                self.blocked_write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            self.send_buf.extend(buf);
            return Poll::Ready(Ok(buf.len()));
        }
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        self.send_buf.extend(buf);
        self.flush_send_buf();
        if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        // Staged records beyond OUTBOX_CAP stay queued — the caller got a
        // full `Ok` and `poll_flush`/the next read drains them.
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Upstream `Close` emits a real close_notify through the cover
        // cipher — a clean TLS shutdown, not an abrupt TCP close.
        if !this.sent_close_notify {
            this.sent_close_notify = true;
            if let Some(cover) = &mut this.cover_write {
                let rec = cover.seal_close_notify();
                this.outbox.extend(&rec);
            }
        }
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque as Vdq;
    use tokio::io::AsyncWriteExt;

    const CCS_RECORD: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

    struct MockCover {
        opens: Vdq<(u8, Vec<u8>)>,
        rekeys: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl MockCover {
        fn new(
            opens: impl IntoIterator<Item = (u8, Vec<u8>)>,
        ) -> (Self, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let rekeys = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            (
                Self {
                    opens: opens.into_iter().collect(),
                    rekeys: std::sync::Arc::clone(&rekeys),
                },
                rekeys,
            )
        }
    }

    impl CoverCipher for MockCover {
        fn open(&mut self, _record: &mut [u8]) -> Option<(u8, Vec<u8>)> {
            self.opens.pop_front()
        }
        fn seal(&mut self, _body: &[u8]) -> Vec<u8> {
            Vec::new()
        }
        fn seal_close_notify(&mut self) -> Vec<u8> {
            Vec::new()
        }
        fn rekey(&mut self) {
            self.rekeys
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        fn seal_key_update_response(&mut self) -> Option<Vec<u8>> {
            self.rekeys
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(vec![0x16, 0x03, 0x03, 0, 5, 24, 0, 0, 1, 0])
        }
    }

    fn stream(authed: bool, cover: Option<MockCover>) -> RestlsStream<tokio::io::DuplexStream> {
        stream_full(authed, cover, None)
    }

    fn stream_full(
        authed: bool,
        cover: Option<MockCover>,
        cover_write: Option<MockCover>,
    ) -> RestlsStream<tokio::io::DuplexStream> {
        let (inner, _peer) = tokio::io::duplex(64);
        RestlsStream::new(
            RestlsUpgraded {
                inner,
                server_random: [7u8; 32],
                client_finished: None,
                authed,
                cover_read: cover.map(|c| Box::new(c) as _),
                cover_write: cover_write.map(|c| Box::new(c) as _),
                tls12_gcm: false,
                gcm_ctr_disabled: false,
                gcm_next_seq: 0,
                cover_hs_pending: Vec::new(),
            },
            wire::derive_secret(b"pw"),
            Vec::new(),
        )
        .unwrap()
    }

    /// A server→client tagged record — `build_tagged_record` is the
    /// client→server direction, so inbound fixtures build the MAC the
    /// way upstream's server does (dir label `server-to-client`).
    fn server_record(data: &[u8], ctr: u64) -> Vec<u8> {
        let secret = wire::derive_secret(b"pw");
        let sr = [7u8; 32];
        let payload_len = AUTH_HEADER_LEN + data.len();
        let mut out = Vec::with_capacity(RECORD_HDR + payload_len);
        out.extend_from_slice(&[0x17, 0x03, 0x03]);
        out.extend_from_slice(&(payload_len as u16).to_be_bytes());
        out.resize(RECORD_HDR + AUTH_HEADER_LEN, 0);
        out.extend_from_slice(data);
        // len‖cmd masked with the data-prefix mask.
        let mut hmask = blake3::Hasher::new_keyed(&secret);
        hmask.update(&sr);
        hmask.update(b"server-to-client");
        hmask.update(&ctr.to_be_bytes());
        hmask.update(&data[..data.len().min(32)]);
        let mask = hmask.finalize();
        let field = &mut out[RECORD_HDR + 8..RECORD_HDR + 12];
        field[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
        field[2..4].copy_from_slice(&[0, 0]);
        for (b, m) in field.iter_mut().zip(mask.as_bytes().iter()) {
            *b ^= m;
        }
        let mut hmac = blake3::Hasher::new_keyed(&secret);
        hmac.update(&sr);
        hmac.update(b"server-to-client");
        hmac.update(&ctr.to_be_bytes());
        hmac.update(&out[..RECORD_HDR]);
        hmac.update(&out[RECORD_HDR + 8..]);
        out[RECORD_HDR..RECORD_HDR + 8].copy_from_slice(&hmac.finalize().as_bytes()[..8]);
        out
    }

    /// A CCS flood must die at upstream's `maxUselessRecords` bound —
    /// stray CCS is legal noise, not an infinite read-loop spin.
    #[test]
    fn stray_ccs_bounded() {
        let mut s = stream(true, None);
        for i in 0..MAX_USELESS_RECORDS {
            s.process_record(CCS_RECORD.to_vec())
                .unwrap_or_else(|e| panic!("CCS {i} rejected early: {e}"));
        }
        assert!(s.process_record(CCS_RECORD.to_vec()).is_err());
    }

    /// A valid tagged record resets the streak — interleaved CCS stays
    /// legal middlebox noise.
    #[test]
    fn ccs_streak_resets_on_real_record() {
        let mut s = stream(true, None);
        for _ in 0..MAX_USELESS_RECORDS {
            s.process_record(CCS_RECORD.to_vec()).unwrap();
        }
        s.process_record(server_record(b"d", 0)).unwrap();
        for _ in 0..MAX_USELESS_RECORDS {
            s.process_record(CCS_RECORD.to_vec()).unwrap();
        }
        assert!(s.process_record(CCS_RECORD.to_vec()).is_err());
    }

    /// A single cover record packed with more handshake messages than
    /// upstream's `maxUselessRecords` bound dies — upstream's
    /// `handlePostHandshakeMessage` ticks `retryCount` per message.
    #[test]
    fn cover_handshake_counts_useless() {
        // MAX+1 complete NST-shaped messages (type 4, len 2) in one
        // record's plaintext.
        let mut packed = Vec::new();
        for _ in 0..=MAX_USELESS_RECORDS {
            packed.extend_from_slice(&[4u8, 0, 0, 2, 0, 0]);
        }
        let (cover, _) = MockCover::new([(TLS_RECORD_HANDSHAKE, packed)]);
        let mut s = stream(true, Some(cover));
        assert!(s.process_record(vec![0x17, 0x03, 0x03, 0, 6]).is_err());
    }

    /// A drip of one-message handshake records accumulates the streak —
    /// upstream's post-handshake `retryCount++` per message never resets
    /// on handshake data, so an endless NST feed dies at the cap.
    #[test]
    fn cover_handshake_records_accumulate_streak() {
        let (cover, _) = MockCover::new(std::iter::repeat_n(
            (TLS_RECORD_HANDSHAKE, vec![4u8, 0, 0, 2, 0, 0]),
            3 * MAX_USELESS_RECORDS as usize,
        ));
        let mut s = stream(true, Some(cover));
        for i in 0..MAX_USELESS_RECORDS {
            s.process_record(vec![0x17, 0x03, 0x03, 0, 6]).unwrap();
            assert_eq!(s.useless_records, i + 1);
        }
        // Record MAX+1 tips the streak past the bound.
        assert!(s.process_record(vec![0x17, 0x03, 0x03, 0, 6]).is_err());
    }

    /// An empty tagged record (fake/`Respond` reply) ticks the streak
    /// instead of resetting it — an endless non-advancing feed dies,
    /// matching upstream's `retryReadRecord`.
    #[test]
    fn empty_tagged_record_counts_useless() {
        let mut s = stream(true, None);
        s.process_record(server_record(b"", 0)).unwrap();
        assert_eq!(s.useless_records, 1);
        // Alternating empty tagged + CCS never resets either.
        s.process_record(CCS_RECORD.to_vec()).unwrap();
        assert_eq!(s.useless_records, 2);
        // A real payload resets.
        s.process_record(server_record(b"d", 1)).unwrap();
        assert_eq!(s.useless_records, 0);
    }

    /// A clean `close_notify` at the streak boundary still surfaces EOF —
    /// upstream returns `io.EOF` unconditionally, it is not counted.
    #[test]
    fn close_notify_at_streak_boundary_is_eof() {
        let (cover, _) = MockCover::new([(TLS_RECORD_ALERT, vec![1, 0])]);
        let mut s = stream(true, Some(cover));
        s.useless_records = MAX_USELESS_RECORDS;
        s.process_record(vec![0x17, 0x03, 0x03, 0, 0]).unwrap();
        assert!(s.eof);
    }

    /// A TLS 1.2 cover's warning alert is tolerated (bounded), not fatal.
    #[test]
    fn tls12_warning_alert_tolerated() {
        let (cover, _) = MockCover::new([(TLS_RECORD_ALERT, vec![1, 90])]);
        let mut s = stream(true, Some(cover));
        // disableCtr drops the inbound nonce-slot rewrite so the mock's
        // alert surfaces (the slot logic is unrelated to alert handling).
        s.tls12_gcm = true;
        s.gcm_ctr_disabled = true;
        s.process_record(vec![0x17, 0x03, 0x03, 0, 0]).unwrap();
        assert!(!s.eof);
    }

    /// A cover alert `close_notify` is a clean EOF, not a stream error.
    #[test]
    fn cover_close_notify_is_eof() {
        let (cover, _) = MockCover::new([(TLS_RECORD_ALERT, vec![1, 0])]);
        let mut s = stream(true, Some(cover));
        s.process_record(vec![0x17, 0x03, 0x03, 0, 0]).unwrap();
        assert!(s.eof);
    }

    /// Any other cover alert stays fatal.
    #[test]
    fn cover_alert_fatal() {
        let (cover, _) = MockCover::new([(TLS_RECORD_ALERT, vec![2, 40])]);
        let mut s = stream(true, Some(cover));
        assert!(s.process_record(vec![0x17, 0x03, 0x03, 0, 0]).is_err());
    }

    /// KeyUpdate rekeys the inbound cover cipher — including when the
    /// handshake message straddles two cover records (upstream buffers
    /// the tail in `c.hand`; dropping it would desync the cipher).
    #[test]
    fn cover_keyupdate_rekeys_across_records() {
        // KeyUpdate(24), len 1, body [0] (update_not_requested) — split
        // after the 2nd header byte.
        let (cover, rekeys) = MockCover::new([
            (TLS_RECORD_HANDSHAKE, vec![24u8, 0x00]),
            (TLS_RECORD_HANDSHAKE, vec![0x00u8, 0x01, 0x00]),
        ]);
        let mut s = stream(true, Some(cover));
        s.accept_cover_record(&mut [0x17, 0x03, 0x03, 0, 2])
            .unwrap();
        assert_eq!(
            rekeys.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "rekeyed on an incomplete KeyUpdate"
        );
        s.accept_cover_record(&mut [0x17, 0x03, 0x03, 0, 3])
            .unwrap();
        assert_eq!(rekeys.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// KeyUpdate(request_update) stages our `key_update_not_requested`
    /// response in the outbox and rekeys BOTH directions.
    #[test]
    fn keyupdate_request_stages_response() {
        let (read, read_rekeys) = MockCover::new([(
            TLS_RECORD_HANDSHAKE,
            vec![24u8, 0, 0, 1, 1], // request_update
        )]);
        let (write, write_rekeys) = MockCover::new([]);
        let mut s = stream_full(true, Some(read), Some(write));
        s.accept_cover_record(&mut [0x17, 0x03, 0x03, 0, 5])
            .unwrap();
        assert_eq!(read_rekeys.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(write_rekeys.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(!s.outbox.is_empty(), "KU response not staged");
    }

    /// A post-handshake message advertising a giant length wedges the
    /// buffer — bound it instead of growing forever.
    #[test]
    fn cover_hs_buf_bounded() {
        let mut s = stream(true, None);
        // Handshake header claiming a 64 KiB body — never completed, so
        // each appended chunk stays buffered until the cap trips.
        let giant = [24u8, 0x01, 0x00, 0x00];
        s.handle_cover_handshake(&giant).unwrap();
        let chunk = vec![0u8; 32 * 1024];
        // 4-byte header + 64 KiB body is the upstream `maxHandshake`
        // bound — the buffer cap is the header plus that body.
        s.handle_cover_handshake(&chunk).unwrap();
        s.handle_cover_handshake(&chunk).unwrap();
        assert!(s.handle_cover_handshake(&chunk).is_err());
    }

    /// Authed mode: a cover `close_notify` must surface EOF on the very
    /// next `poll_read` — upstream's sticky `io.EOF` — not park waiting
    /// for a record that never comes.
    #[tokio::test]
    async fn close_notify_prompt_eof() {
        use std::future::poll_fn;
        let (cover, _) = MockCover::new([(TLS_RECORD_ALERT, vec![1, 0])]);
        let mut s = stream(true, Some(cover));
        s.process_record(vec![0x17, 0x03, 0x03, 0, 0]).unwrap();
        let mut buf_storage = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut buf_storage);
        poll_fn(|cx| {
            let poll = std::pin::Pin::new(&mut s).poll_read(cx, &mut buf);
            assert!(poll.is_ready(), "close_notify did not surface EOF");
            poll
        })
        .await
        .unwrap();
        assert!(buf.filled().is_empty());
    }

    /// Transparent mode: an empty decrypted appdata record (padding) is
    /// useless noise — skipping it must not read as EOF. The read pends
    /// for the next record instead.
    #[tokio::test]
    async fn transparent_empty_appdata_skips() {
        use std::future::poll_fn;
        let (cover, _) = MockCover::new([(TLS_RECORD_APPLICATION_DATA, Vec::new())]);
        let (inner, mut peer) = tokio::io::duplex(64);
        let mut s = {
            RestlsStream::new(
                RestlsUpgraded {
                    inner,
                    server_random: [7u8; 32],
                    client_finished: None,
                    authed: false,
                    cover_read: Some(Box::new(cover)),
                    cover_write: None,
                    tls12_gcm: false,
                    gcm_ctr_disabled: false,
                    gcm_next_seq: 0,
                    cover_hs_pending: Vec::new(),
                },
                wire::derive_secret(b"pw"),
                Vec::new(),
            )
            .unwrap()
        };
        // Feed one full record; the mock decrypts it to empty appdata.
        tokio::io::AsyncWriteExt::write_all(&mut peer, &[0x17, 0x03, 0x03, 0, 1, 0])
            .await
            .unwrap();
        let mut buf_storage = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut buf_storage);
        let polled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            poll_fn(|cx| std::pin::Pin::new(&mut s).poll_read(cx, &mut buf)),
        )
        .await;
        assert!(
            polled.is_err(),
            "empty appdata read as EOF instead of being skipped"
        );
    }

    /// Transparent mode: stray CCS records are skipped (bounded) before
    /// real cover data — the read loop must not tick counters or die.
    #[tokio::test]
    async fn transparent_ccs_skipped_then_data() {
        use std::future::poll_fn;
        let (cover, _) = MockCover::new([(TLS_RECORD_APPLICATION_DATA, b"hi".to_vec())]);
        let (inner, mut peer) = tokio::io::duplex(256);
        let mut s = {
            RestlsStream::new(
                RestlsUpgraded {
                    inner,
                    server_random: [7u8; 32],
                    client_finished: None,
                    authed: false,
                    cover_read: Some(Box::new(cover)),
                    cover_write: None,
                    tls12_gcm: false,
                    gcm_ctr_disabled: false,
                    gcm_next_seq: 0,
                    cover_hs_pending: Vec::new(),
                },
                wire::derive_secret(b"pw"),
                Vec::new(),
            )
            .unwrap()
        };
        for _ in 0..3 {
            peer.write_all(&CCS_RECORD).await.unwrap();
        }
        peer.write_all(&[0x17, 0x03, 0x03, 0, 1, 0]).await.unwrap();
        let mut buf_storage = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut buf_storage);
        poll_fn(|cx| std::pin::Pin::new(&mut s).poll_read(cx, &mut buf))
            .await
            .unwrap();
        assert_eq!(buf.filled(), b"hi");
        // The productive record reset the useless-record streak.
        assert_eq!(s.useless_records, 0);
    }

    /// Transparent mode: a CCS flood dies at the useless-record bound —
    /// same bound as the authed path.
    #[tokio::test]
    async fn transparent_ccs_bounded() {
        use std::future::poll_fn;
        let (cover, _) = MockCover::new([]);
        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut s = {
            RestlsStream::new(
                RestlsUpgraded {
                    inner,
                    server_random: [7u8; 32],
                    client_finished: None,
                    authed: false,
                    cover_read: Some(Box::new(cover)),
                    cover_write: None,
                    tls12_gcm: false,
                    gcm_ctr_disabled: false,
                    gcm_next_seq: 0,
                    cover_hs_pending: Vec::new(),
                },
                wire::derive_secret(b"pw"),
                Vec::new(),
            )
            .unwrap()
        };
        for _ in 0..=MAX_USELESS_RECORDS {
            peer.write_all(&CCS_RECORD).await.unwrap();
        }
        let mut buf_storage = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut buf_storage);
        let res = poll_fn(|cx| std::pin::Pin::new(&mut s).poll_read(cx, &mut buf)).await;
        assert!(res.is_err(), "CCS flood should die at the bound");
    }

    /// Two complete messages in one record both process; a trailing
    /// partial stays buffered for the next record.
    #[test]
    fn cover_hs_multi_message_drain() {
        let (cover, rekeys) = MockCover::new([]);
        let mut s = stream(true, Some(cover));
        // Two KeyUpdates + a partial third header.
        let buf = [
            24u8, 0, 0, 1, 0, // KU (update_not_requested)
            24, 0, 0, 1, 0, // KU
            24, 0, // partial
        ];
        s.handle_cover_handshake(&buf).unwrap();
        assert_eq!(rekeys.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(s.cover_hs_buf, vec![24, 0]);
        // Completing the partial triggers the third rekey.
        s.handle_cover_handshake(&[0, 1, 0]).unwrap();
        assert_eq!(rekeys.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert!(s.cover_hs_buf.is_empty());
    }

    /// A KeyUpdate coalesced into the server Finished record arrives via
    /// `cover_hs_pending` — `RestlsStream::new` consumes it eagerly or
    /// the cover epoch desyncs.
    #[test]
    fn pending_leftover_keyupdate_rekeys() {
        // KU(update_requested): typ 24, len 1, body [1].
        let (read, read_rekeys) = MockCover::new([]);
        let (write, write_rekeys) = MockCover::new([]);
        let (inner, _peer) = tokio::io::duplex(64);
        let s = RestlsStream::new(
            RestlsUpgraded {
                inner,
                server_random: [7u8; 32],
                client_finished: None,
                authed: true,
                cover_read: Some(Box::new(read)),
                cover_write: Some(Box::new(write)),
                tls12_gcm: false,
                gcm_ctr_disabled: false,
                gcm_next_seq: 0,
                cover_hs_pending: vec![0x18, 0x00, 0x00, 0x01, 0x01],
            },
            wire::derive_secret(b"pw"),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(read_rekeys.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(write_rekeys.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(!s.outbox.is_empty(), "KU response must be staged");
    }
}
