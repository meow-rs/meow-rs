// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! PATCH(18): the process-wide data-plane crypto pool — a bounded set of
//! resident `std` threads shared by every outbound pump and every inbound
//! listener actor (the spec's "persistent worker pool" correction). Each
//! receive actor stays fully serial: it verifies and demuxes each wire
//! datagram itself, hands the DATA arm's AEAD open to this pool as a
//! [`CryptoJob`], then applies the results in the batch's original
//! arrival order. A `CryptoJob` moves the *whole owned receive buffer*
//! through the pool — the worker opens `buf[DATA_PAYLOAD_OFF..wire_len]`
//! in place — so the zero-copy `rx_slots` contract survives: the same
//! `Vec` becomes the `Bytes` the inner stack consumes, no copy anywhere.
//!
//! PATCH(19): the same pool seals the TX direction. A [`TxCryptoJob`]
//! carries the inner packet *and* a wire-side scratch buffer through
//! the pool — the worker writes
//! `type‖sending_index‖counter‖ciphertext‖tag` into the scratch and
//! truncates it to the datagram — so the pump/actor post-pass moves the
//! finished datagram to the outbox untouched. The seal direction needs
//! its own job type rather than a generalized `CryptoJob` enum: the
//! buffer ownership contracts differ (open: one owned Vec; seal: two
//! owned Vecs with different post-pass fates). Both directions share
//! the resident threads through the [`JobChunk`] channel enum — a pass
//! is always homogeneous, so `run` only ever sees `Rx` chunks and
//! `run_tx` only `Tx`, each `debug_assert`ed at the unwrap.
//!
//! Why this shape: `std::thread::scope`'s spawn cost (~50 µs per thread
//! per pass) exceeds an entire batch's AEAD time, so per-batch threads
//! lose to serial. Resident workers pay one `mpsc` wakeup (~1–3 µs) per
//! chunk. Dispatch is chunk-based — contiguous `Vec` ranges, one
//! message per worker — and each worker's paired result channel
//! returns its chunk in order, so reassembly is positional: chunk
//! boundaries guarantee the original order with no reorder buffer.
//!
//! Worker count `W = min(available_parallelism - 1, 4)`, floor 1 — the
//! `- 1` keeps a core free for the actor's own serial work (verify,
//! post-pass, smoltcp); `4` is where the per-session replay-window
//! mutex and the single consumer stop scaling anyway. `W <= 1` (or a
//! batch of `n <= 2`) skips the pool entirely and runs inline — the
//! serial fallback the spec requires, identical in both directions.

use std::sync::mpsc;
use std::sync::OnceLock;

use parking_lot::Mutex;

use crate::noise::errors::WireGuardError;
use crate::noise::{SessionHandle, DATA_OVERHEAD_SZ, DATA_PAYLOAD_OFF};

/// One data-packet open, moved end to end through the pool: the owned
/// wire datagram plus the crypto the demux resolved for it.
pub struct CryptoJob {
    /// The whole wire datagram buffer — `buf[..wire_len]` is the
    /// datagram (type‖r_idx‖counter‖ciphertext‖tag); the Vec itself may
    /// be longer (a receive slot keeps its window). The worker opens
    /// `buf[DATA_PAYLOAD_OFF..wire_len]` in place.
    pub buf: Vec<u8>,
    /// The wire datagram's length within `buf`.
    pub wire_len: usize,
    /// `receiver_idx` from the DATA header — the post-pass needs it for
    /// `handle_decrypted_data`'s session bookkeeping.
    pub receiver_idx: u32,
    /// `counter` from the DATA header — the AEAD nonce and replay key.
    counter: u64,
    /// The session's shared crypto, resolved by the actor while it still
    /// held `&mut Tunn`. `None` when no session held that index — the
    /// job then reports `NoCurrentSession` just as the serial path does.
    crypto: Option<SessionHandle>,
    /// Caller-owned context tag — the post-pass's index back into its
    /// own bookkeeping (rx-slot number, peer-slot/src tuple index).
    /// Riding *inside* the job rather than a parallel Vec keeps the
    /// mapping exact even if `run` ever drops a dead worker's chunk:
    /// positional zips would silently shift every later result onto
    /// the wrong context. The pool never reads or writes it.
    pub tag: usize,
    /// `None` until a worker (or the serial shortcut) fills it: the
    /// plaintext length on success.
    pub result: Option<Result<usize, WireGuardError>>,
}

impl CryptoJob {
    /// Build a job from the classified DATA packet: `buf` is the owned
    /// wire datagram, `wire_len` its bound, `crypto` the
    /// `Tunn::session_handle_for` result for `receiver_idx`, and `tag`
    /// the caller's context index the post-pass maps the result back
    /// through. `tag` is a constructor input — a defaulted tag would
    /// silently map every forgotten job onto context 0.
    pub fn new(
        buf: Vec<u8>,
        wire_len: usize,
        receiver_idx: u32,
        counter: u64,
        crypto: Option<SessionHandle>,
        tag: usize,
    ) -> Self {
        Self {
            buf,
            wire_len,
            receiver_idx,
            counter,
            crypto,
            tag,
            result: None,
        }
    }

    /// The AEAD open itself — the only work that travels to a worker
    /// thread. Index/mutex discipline lives in
    /// `SessionCrypto::receive_packet_data_in_place`: concurrent opens
    /// on one session are replay-safe because the counter mark, not the
    /// quick check, is authoritative under the shared mutex.
    fn decrypt(&mut self) {
        self.result = Some(match self.crypto.as_ref() {
            Some(handle) => {
                if self.wire_len < DATA_OVERHEAD_SZ || self.wire_len > self.buf.len() {
                    // A mis-constructed job can only come from a caller
                    // bug — same verdict parse_incoming_packet gives.
                    Err(WireGuardError::InvalidPacket)
                } else {
                    handle.open_in_place(
                        self.receiver_idx,
                        self.counter,
                        &mut self.buf[DATA_PAYLOAD_OFF..self.wire_len],
                    )
                }
            }
            None => Err(WireGuardError::NoCurrentSession),
        });
    }
}

/// One data-packet seal, moved end to end through the pool — the TX
/// twin of [`CryptoJob`]. Kept a sibling type rather than folding into
/// a job enum because the buffer contract differs: a seal job owns
/// *two* Vecs with different post-pass fates — `inner` returns to the
/// caller regardless of outcome (the caller decides whether it goes
/// back to `tx_pool` or drops), while `wire` carries the finished
/// datagram to the outbox on success and to the scratch pool on
/// failure.
pub struct TxCryptoJob {
    /// The inner packet — moved out of `device.tx_queue` / `inject_rx`.
    /// The worker only reads it; the post-pass owns its return path.
    pub inner: Vec<u8>,
    /// The wire output buffer — a `take_scratch()` Vec at full scratch
    /// length. The worker writes `type‖sending_index‖counter‖
    /// ciphertext‖tag` at its front and truncates it to the wire
    /// length on success; on failure it stays full-size, so
    /// `return_scratch` accepts it either way.
    pub wire: Vec<u8>,
    /// The counter the caller block-reserved for this job
    /// (`SessionHandle::reserve_tx_counters`) — the AEAD nonce and the
    /// wire header's counter field.
    counter: u64,
    /// The session's shared crypto, captured in Phase A through
    /// `Tunn::current_session_handle`. Non-optional by contract —
    /// unlike the RX [`CryptoJob`], a TX job is only built once the
    /// caller confirmed a session exists: a peer with none takes the
    /// serial `encapsulate` arm, where `queue_packet` + the handshake
    /// chain live. `Option` here would encode a silent drop the serial
    /// semantics never had, so a no-session caller cannot construct
    /// this type at all.
    crypto: SessionHandle,
    /// Caller ctxs side-table dense index — the multi-peer listener's
    /// `ctxs` slot whose peer this job's post-pass resolves (the
    /// single-peer pump uses the job's own position). The same
    /// opaque-tag pattern as [`CryptoJob::tag`]: the pool never reads
    /// or writes it.
    pub tag: usize,
    /// `None` until a worker (or the serial shortcut) fills it: the
    /// wire length on success.
    pub result: Option<Result<usize, WireGuardError>>,
}

impl TxCryptoJob {
    /// Build a job from a drained inner packet: `inner` is the packet
    /// the caller owns (a `tx_queue` Vec or an inject copy), `wire` a
    /// fresh scratch buffer, `counter` one value out of the batch's
    /// block reservation, `crypto` the session handle Phase A
    /// captured, and `tag` the caller's `ctxs` side-table index.
    /// Both `crypto` and `tag` are constructor inputs — a no-session
    /// job would silently drop where the serial semantics queue +
    /// handshake, and a defaulted tag would silently map `ctxs[0]`.
    pub fn new(
        inner: Vec<u8>,
        wire: Vec<u8>,
        counter: u64,
        crypto: SessionHandle,
        tag: usize,
    ) -> Self {
        Self {
            inner,
            wire,
            counter,
            crypto,
            tag,
            result: None,
        }
    }

    /// The AEAD seal itself — the only work that travels to a worker
    /// thread. Writes the whole wire datagram into `self.wire` and
    /// truncates it to the wire length; `format_packet_data_at` keeps
    /// `format_packet_data`'s panic-on-undersize contract, which the
    /// guard below discharges first — a breach is a caller bug (the
    /// drain's Phase-A scratch check), reported `InvalidPacket` rather
    /// than panicking the pool.
    fn seal(&mut self) {
        self.result = Some(if self.inner.len() + DATA_OVERHEAD_SZ > self.wire.len() {
            Err(WireGuardError::InvalidPacket)
        } else {
            let n = self
                .crypto
                .seal_at(&self.inner, &mut self.wire, self.counter);
            debug_assert_eq!(n, self.inner.len() + DATA_OVERHEAD_SZ);
            self.wire.truncate(n);
            Ok(n)
        });
    }
}

/// A chunk of jobs travelling to or from a worker — one contiguous job
/// range, one message, in one direction. The pool's two entry points
/// share the resident threads but a pass is always homogeneous:
/// `run` only sends and unwraps `Rx`, `run_tx` only `Tx` — a foreign
/// variant coming back can only mean a worker replayed a stale chunk,
/// which the caller treats like a mid-pass worker death (and
/// `debug_assert`s away).
enum JobChunk {
    Rx(Vec<CryptoJob>),
    Tx(Vec<TxCryptoJob>),
}

/// The process-wide pool instance [`CryptoPool::shared`] lazily
/// resolves — module-scope so a `#[cfg(test)]` probe can observe
/// whether the `n <= 2` serial shortcuts really run before init.
static POOL: OnceLock<CryptoPool> = OnceLock::new();

/// The resident worker set. One [`CryptoPool::shared`] instance serves
/// the whole process; `run`/`run_tx` serialize callers internally so
/// two actors can never interleave their chunks on a worker's queue.
pub struct CryptoPool {
    /// Job chunk → worker.
    senders: Vec<mpsc::Sender<JobChunk>>,
    /// Worker → finished chunk, one receiver per worker so the caller
    /// drains them in chunk order (the no-reorder guarantee above).
    /// The mutex serializes whole passes: two actors' `run` calls queue
    /// back to back rather than mixing chunks on a worker.
    inner: Mutex<Vec<mpsc::Receiver<JobChunk>>>,
}

impl CryptoPool {
    /// A pool with `workers` resident threads. `workers <= 1` spawns
    /// nothing — `run`/`run_tx` then always take the serial path,
    /// which is also what keeps a single-core or `new(1)` test from
    /// paying a dead thread.
    pub fn new(workers: usize) -> Self {
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        if workers > 1 {
            for _ in 0..workers {
                let (job_tx, job_rx) = mpsc::channel::<JobChunk>();
                let (done_tx, done_rx) = mpsc::channel::<JobChunk>();
                std::thread::Builder::new()
                    .name("wg-crypto".into())
                    .spawn(move || {
                        while let Ok(mut chunk) = job_rx.recv() {
                            match &mut chunk {
                                JobChunk::Rx(jobs) => {
                                    for job in jobs {
                                        job.decrypt();
                                    }
                                }
                                JobChunk::Tx(jobs) => {
                                    for job in jobs {
                                        job.seal();
                                    }
                                }
                            }
                            if done_tx.send(chunk).is_err() {
                                return;
                            }
                        }
                    })
                    .expect("wg-crypto worker spawn");
                senders.push(job_tx);
                receivers.push(done_rx);
            }
        }
        Self {
            senders,
            inner: Mutex::new(receivers),
        }
    }

    /// `min(cores - 1, 4)`, floor 1 — see the module docs for the
    /// rationale. Worker *threads*, not chunk count: a pass dispatches
    /// every chunk to a resident thread and joins on the results.
    fn default_workers() -> usize {
        std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).clamp(1, 4))
    }

    /// The process-wide pool — one resident set shared by every
    /// outbound pump and every inbound listener actor. `OnceLock` init
    /// spawns the workers on first use; callers go through
    /// [`run_shared`](Self::run_shared) /
    /// [`run_tx_shared`](Self::run_tx_shared), whose `n <= 2` serial
    /// shortcut keeps even that lazy — a process with no WireGuard
    /// traffic (or only small batches) never resolves `shared()` at
    /// all, so the workers spawn on the first genuinely parallel pass.
    pub fn shared() -> &'static CryptoPool {
        POOL.get_or_init(|| CryptoPool::new(Self::default_workers()))
    }

    /// Test probe: has [`shared`](Self::shared) been resolved yet?
    /// `parallel_tx_serial_fallback` compares this across a small-batch
    /// `run_tx_shared` to pin the serial shortcut running *before* the
    /// pool's `OnceLock` init (an earlier test may legitimately have
    /// resolved it, so the pin is on the *transition*, not the state).
    #[cfg(test)]
    fn shared_resolved() -> bool {
        POOL.get().is_some()
    }

    /// `run` on the process-wide [`shared`](Self::shared) pool — the
    /// entry point both receive actors use. The `n <= 2` serial
    /// shortcut runs *before* `shared()` is resolved, so small batches
    /// never spawn the resident threads; bigger batches delegate to
    /// `shared().run` with its full contract.
    pub fn run_shared(jobs: &mut Vec<CryptoJob>) {
        if jobs.len() <= 2 {
            Self::run_serial(jobs);
            return;
        }
        Self::shared().run(jobs);
    }

    /// [`run_shared`](Self::run_shared)'s TX twin — the entry point the
    /// pump's and the listener actor's egress drains use. Same lazy
    /// `n <= 2` shortcut, same process-wide pool underneath.
    pub fn run_tx_shared(jobs: &mut Vec<TxCryptoJob>) {
        if jobs.len() <= 2 {
            Self::run_tx_serial(jobs);
            return;
        }
        Self::shared().run_tx(jobs);
    }

    /// The serial fallback — every job's open inline on the calling
    /// thread, in order.
    fn run_serial(jobs: &mut [CryptoJob]) {
        for job in jobs.iter_mut() {
            job.decrypt();
        }
    }

    /// [`run_serial`](Self::run_serial)'s TX twin — inline seals, in
    /// order.
    fn run_tx_serial(jobs: &mut [TxCryptoJob]) {
        for job in jobs.iter_mut() {
            job.seal();
        }
    }

    /// Run one batch: fill every job's `result`, preserving `jobs`'s
    /// original order. Serial when the batch is too small to pay two
    /// channel hops or when no workers exist; otherwise contiguous
    /// chunks go out one per worker and come back in chunk order — the
    /// positional merge the module docs describe.
    ///
    /// The calling thread blocks until the pass joins; concurrent
    /// `run`s serialize through `inner`'s mutex, so two actors' passes
    /// queue back to back — they never interleave chunks on a worker.
    /// The join is a blocking `mpsc::recv` hold on the caller, so the
    /// caller's own threading matters: a dedicated actor thread (the
    /// inbound listener's) blocks outright — nothing else lives on it
    /// — while a caller on a shared tokio worker (the outbound pump's
    /// `tokio::spawn`'d task) must wrap the call in
    /// `tokio::task::block_in_place` so the wait moves off the
    /// runtime's worker set; a bare call would stall the worker's
    /// other tasks for the pass's duration.
    pub fn run(&self, jobs: &mut Vec<CryptoJob>) {
        self.dispatch(jobs, JobChunk::Rx, |chunk| match chunk {
            JobChunk::Rx(jobs) => Some(jobs),
            JobChunk::Tx(_) => None,
        });
    }

    /// [`run`](Self::run)'s TX twin — one seal batch through the same
    /// resident workers, same order-preserving merge, same serial
    /// fallbacks, same caller-threading contract (shared tokio workers
    /// wrap it in `block_in_place`).
    pub fn run_tx(&self, jobs: &mut Vec<TxCryptoJob>) {
        self.dispatch(jobs, JobChunk::Tx, |chunk| match chunk {
            JobChunk::Tx(jobs) => Some(jobs),
            JobChunk::Rx(_) => None,
        });
    }

    /// The chunk-split / dispatch / positional-merge both directions
    /// share — the job-type-generic half of `run`. `wrap` packs a
    /// chunk for the channel, `unwrap` unpacks the returned message
    /// (failing only on a foreign variant — impossible while passes
    /// stay homogeneous, guarded by `debug_assert` and treated like a
    /// dead worker's lost chunk in release).
    fn dispatch<T, W, U>(&self, jobs: &mut Vec<T>, wrap: W, unwrap: U)
    where
        T: JobProcess + Send,
        W: Fn(Vec<T>) -> JobChunk,
        U: Fn(JobChunk) -> Option<Vec<T>>,
    {
        let n = jobs.len();
        let workers = n.min(self.senders.len());
        if workers <= 1 || n <= 2 {
            for job in jobs.iter_mut() {
                job.process();
            }
            return;
        }

        let rxs = self.inner.lock();

        // Split into `workers` contiguous chunks of ceil(n/workers).
        let per = n.div_ceil(workers);
        let mut chunks: Vec<Vec<T>> = Vec::with_capacity(workers);
        {
            let mut iter = std::mem::take(jobs).into_iter();
            let mut left = n;
            while left > 0 {
                let take = left.min(per);
                chunks.push(iter.by_ref().take(take).collect());
                left -= take;
            }
        }

        // Per-chunk slots keep the merge positional even when a dead
        // worker's chunk lands inline.
        let mut done: Vec<Option<Vec<T>>> = Vec::new();
        done.resize_with(chunks.len(), || None);
        let mut waiting = Vec::with_capacity(chunks.len());
        for (i, chunk) in chunks.into_iter().enumerate() {
            match self.senders[i].send(wrap(chunk)) {
                Ok(()) => waiting.push(i),
                Err(mpsc::SendError(msg)) => {
                    // Dead worker — run the chunk here rather than lose
                    // its datagrams. Cold path: a resident worker only
                    // dies on panic, so the warn never sits in the hot
                    // loop.
                    tracing::warn!(
                        "wg-crypto worker {i} died before dispatch; running its chunk inline"
                    );
                    // The message we just built can only hold our own
                    // variant — unwrap cannot miss.
                    let mut chunk = unwrap(msg).expect("own chunk variant");
                    for job in &mut chunk {
                        job.process();
                    }
                    done[i] = Some(chunk);
                }
            }
        }
        for i in waiting {
            match rxs[i].recv() {
                Ok(msg) => match unwrap(msg) {
                    Some(chunk) => done[i] = Some(chunk),
                    None => {
                        // A foreign variant can only come from a worker
                        // replaying a stale chunk — impossible while
                        // passes serialize through `inner`; treated as
                        // a mid-pass loss in release.
                        debug_assert!(false, "worker returned a foreign chunk variant");
                        tracing::warn!(
                            "wg-crypto worker {i} returned a foreign chunk; its datagrams drop"
                        );
                    }
                },
                // RecvErr ⇒ the worker died mid-pass; the chunk is gone
                // with it — a drop the caller tolerates like a UDP
                // drop, but never a silent one.
                Err(_) => {
                    tracing::warn!(
                        "wg-crypto worker {i} died mid-pass; its chunk's datagrams drop"
                    );
                }
            }
        }
        for chunk in done.into_iter().flatten() {
            jobs.extend(chunk);
        }
    }
}

/// The per-job unit of work both job types share — `decrypt` for RX,
/// `seal` for TX — so [`CryptoPool::dispatch`] stays job-type-generic
/// without trait objects or enum-wrapped jobs.
trait JobProcess {
    fn process(&mut self);
}

impl JobProcess for CryptoJob {
    fn process(&mut self) {
        self.decrypt();
    }
}

impl JobProcess for TxCryptoJob {
    fn process(&mut self) {
        self.seal();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::Tunn;
    use crate::x25519;

    /// A fake crypto handle is impossible (the job stores a real
    /// `Option<SessionHandle>`), so these exercise the pool's own
    /// contract — chunking, ordering, the serial fallback — through
    /// `crypto: None` jobs, whose `decrypt` resolves to
    /// `NoCurrentSession` per job without needing a session.
    fn no_session_jobs(n: usize) -> Vec<CryptoJob> {
        (0..n)
            .map(|i| CryptoJob::new(vec![0u8; 64], 64, 0, 0, None, i))
            .collect()
    }

    /// Two `Tunn`s with a completed handshake — the only way to mint a
    /// real `SessionHandle` for a TX job (the session types stay
    /// crate-private; `Tunn`'s own ring mints them).
    fn session_pair() -> (Tunn, Tunn) {
        let a_secret = x25519::StaticSecret::from([0xA1; 32]);
        let a_public = x25519::PublicKey::from(&a_secret);
        let b_secret = x25519::StaticSecret::from([0xB2; 32]);
        let b_public = x25519::PublicKey::from(&b_secret);
        let mut a = Tunn::new(a_secret, b_public, None, None, 0, None);
        let mut b = Tunn::new(b_secret, a_public, None, None, 0, None);
        let mut wire = vec![0u8; 2048];
        let init = {
            let crate::noise::TunnResult::WriteToNetwork(p) =
                a.format_handshake_initiation(&mut wire, false)
            else {
                panic!("initiator formats an initiation");
            };
            p.to_vec()
        };
        let resp = {
            let crate::noise::TunnResult::WriteToNetwork(p) = b.decapsulate(None, &init, &mut wire)
            else {
                panic!("responder answers the initiation");
            };
            p.to_vec()
        };
        let keepalive = {
            let crate::noise::TunnResult::WriteToNetwork(p) = a.decapsulate(None, &resp, &mut wire)
            else {
                panic!("initiator consumes the response");
            };
            p.to_vec()
        };
        let res = b.decapsulate(None, &keepalive, &mut wire);
        assert!(
            matches!(res, crate::noise::TunnResult::Done),
            "responder consumes the keepalive, got {res:?}"
        );
        (a, b)
    }

    /// One more full handshake round on an already-linked pair —
    /// bumps `current` to a fresh session on both sides, the same
    /// rekey a mid-batch rotation performs.
    fn rotate_session(a: &mut Tunn, b: &mut Tunn) {
        let mut wire = vec![0u8; 2048];
        let init = {
            let crate::noise::TunnResult::WriteToNetwork(p) =
                a.format_handshake_initiation(&mut wire, false)
            else {
                panic!("initiator re-formats an initiation");
            };
            p.to_vec()
        };
        let resp = {
            let crate::noise::TunnResult::WriteToNetwork(p) = b.decapsulate(None, &init, &mut wire)
            else {
                panic!("responder answers the re-initiation");
            };
            p.to_vec()
        };
        let keepalive = {
            let crate::noise::TunnResult::WriteToNetwork(p) = a.decapsulate(None, &resp, &mut wire)
            else {
                panic!("initiator consumes the re-response");
            };
            p.to_vec()
        };
        let res = b.decapsulate(None, &keepalive, &mut wire);
        assert!(
            matches!(res, crate::noise::TunnResult::Done),
            "responder consumes the re-keepalive, got {res:?}"
        );
    }

    /// A minimal valid IPv4 inner — `validate_decapsulated_packet`
    /// checks the version nibble and that the header's total length
    /// (24) does not exceed the packet; `tag` in the last byte keeps
    /// job identity observable across the merge.
    fn inner_packet(tag: u8) -> Vec<u8> {
        vec![
            0x45, 0, 0, 0x18, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0xde, 0xad, 0xbe,
            tag,
        ]
    }

    /// A TX batch over a real session: `handle`'s counters block-
    /// reserved, each job's `inner` stamped with its index so merge
    /// order is observable, each `wire` full-size scratch.
    fn tx_jobs(handle: &SessionHandle, base: u64, n: usize) -> Vec<TxCryptoJob> {
        (0..n)
            .map(|i| {
                TxCryptoJob::new(
                    inner_packet(i as u8),
                    vec![0u8; 2048],
                    base + i as u64,
                    handle.clone(),
                    i,
                )
            })
            .collect()
    }

    #[test]
    fn serial_fallback_small_batch() {
        // n <= 2 always runs inline — even with workers available.
        let pool = CryptoPool::new(4);
        for n in [0usize, 1, 2] {
            let mut jobs = no_session_jobs(n);
            pool.run(&mut jobs);
            assert_eq!(jobs.len(), n);
            for (i, job) in jobs.iter().enumerate() {
                assert!(
                    matches!(job.result, Some(Err(WireGuardError::NoCurrentSession))),
                    "job {i} must be resolved"
                );
            }
        }
    }

    #[test]
    fn parallel_preserves_job_order() {
        let pool = CryptoPool::new(4);
        let mut jobs: Vec<CryptoJob> = (0..64u32)
            .map(|i| {
                let mut job = CryptoJob::new(vec![0u8; 64], 64, i, i as u64, None, i as usize);
                // Stamp the job's identity into its buffer so the merge
                // order is checkable after the pass.
                job.buf[0] = i as u8;
                job
            })
            .collect();
        pool.run(&mut jobs);
        assert_eq!(jobs.len(), 64);
        for (i, job) in jobs.iter().enumerate() {
            assert_eq!(job.buf[0] as usize, i, "job order must be preserved");
            assert!(matches!(
                job.result,
                Some(Err(WireGuardError::NoCurrentSession))
            ));
        }
    }

    #[test]
    fn serial_fallback_without_workers() {
        // new(1) spawns nothing; run still resolves every job in place.
        let pool = CryptoPool::new(1);
        let mut jobs = no_session_jobs(8);
        pool.run(&mut jobs);
        assert_eq!(jobs.len(), 8);
        for job in &jobs {
            assert!(matches!(
                job.result,
                Some(Err(WireGuardError::NoCurrentSession))
            ));
        }
    }

    /// PATCH(19): the TX serial fallback — `n <= 2` resolves inline on
    /// both entry points (`run_tx` and `run_tx_shared`), and `new(1)`
    /// resolves a full batch without workers. TX jobs carry a real
    /// session (a `None` crypto cannot be constructed — no-session TX
    /// traffic takes the caller's serial arm), so the pin is on every
    /// job sealing, not on an error verdict.
    #[test]
    fn parallel_tx_serial_fallback() {
        let (a, _b) = session_pair();
        let handle = a.current_session_handle().expect("session is up");

        let pool = CryptoPool::new(4);
        for n in [0usize, 1, 2] {
            let base = handle.reserve_tx_counters(n);
            let mut jobs = tx_jobs(&handle, base, n);
            pool.run_tx(&mut jobs);
            assert_eq!(jobs.len(), n);
            for (i, job) in jobs.iter().enumerate() {
                assert!(
                    matches!(job.result, Some(Ok(_))),
                    "job {i} must be resolved"
                );
            }
        }

        // `run_tx_shared` takes the same inline arm for a small batch —
        // and the shortcut must run *before* `shared()` resolves the
        // process-wide `OnceLock`. The pin is on the transition (an
        // earlier test in this binary may legitimately have resolved
        // the pool): a 2-job pass must not flip it.
        let resolved = CryptoPool::shared_resolved();
        let base = handle.reserve_tx_counters(2);
        let mut jobs = tx_jobs(&handle, base, 2);
        CryptoPool::run_tx_shared(&mut jobs);
        for job in &jobs {
            assert!(matches!(job.result, Some(Ok(_))));
        }
        assert_eq!(
            CryptoPool::shared_resolved(),
            resolved,
            "the n <= 2 shortcut must run before shared() init"
        );

        // new(1) spawns nothing; run_tx still resolves every job.
        let pool = CryptoPool::new(1);
        let base = handle.reserve_tx_counters(8);
        let mut jobs = tx_jobs(&handle, base, 8);
        pool.run_tx(&mut jobs);
        assert_eq!(jobs.len(), 8);
        for job in &jobs {
            assert!(matches!(job.result, Some(Ok(_))));
        }
    }

    /// PATCH(19): 64 real seals through the pool — job order preserved
    /// in the merged vec (identity rides `inner`, which the seal never
    /// rewrites), every result is `Ok(inner + DATA_OVERHEAD_SZ)`, the
    /// wire headers carry the reserved counters in order, and the peer
    /// opens every datagram back to its inner packet end to end.
    #[test]
    fn parallel_tx_order_preserved() {
        let (a, mut b) = session_pair();
        let handle = a.current_session_handle().expect("session is up");
        let base = handle.reserve_tx_counters(64);
        let mut jobs = tx_jobs(&handle, base, 64);

        let pool = CryptoPool::new(4);
        pool.run_tx(&mut jobs);

        assert_eq!(jobs.len(), 64);
        let mut wire = vec![0u8; 2048];
        for (i, job) in jobs.iter().enumerate() {
            // Merge order: the job at position i is the one built at i.
            assert_eq!(
                *job.inner.last().expect("inner payload"),
                i as u8,
                "job order must be preserved"
            );
            let Some(Ok(wire_len)) = job.result else {
                panic!("job {i} must seal, got {:?}", job.result);
            };
            assert_eq!(wire_len, job.inner.len() + DATA_OVERHEAD_SZ);
            assert_eq!(job.wire.len(), wire_len, "wire truncated to the datagram");
            // Header: DATA type, then the reserved counter in position.
            assert_eq!(u32::from_le_bytes(job.wire[0..4].try_into().unwrap()), 4);
            assert_eq!(
                u64::from_le_bytes(job.wire[8..16].try_into().unwrap()),
                base + i as u64,
                "the wire header carries the job's reserved counter"
            );
            // The peer opens it back to the same inner packet.
            let res = b.decapsulate(None, &job.wire[..wire_len], &mut wire);
            match res {
                crate::noise::TunnResult::WriteToTunnelV4(b_out, _)
                | crate::noise::TunnResult::WriteToTunnelV6(b_out, _) => {
                    assert_eq!(b_out, &job.inner[..], "decrypted inner matches");
                }
                other => panic!("peer must decrypt job {i}'s datagram, got {other:?}"),
            }
        }
    }

    /// PATCH(19): a handle captured in Phase A outlives the session it
    /// cloned — eight rotations fill the whole session ring and evict
    /// the original slot, yet the `Arc`'d crypto still seals a
    /// well-formed datagram (exactly the mid-batch-rotation window the
    /// serial path's per-packet `current` re-read had), while
    /// `current_session_handle` now returns the newest session and its
    /// seal decrypts at the peer.
    #[test]
    fn parallel_tx_session_rotation_mid_batch() {
        let (mut a, mut b) = session_pair();
        let stale = a.current_session_handle().expect("session is up");
        let stale_peer_idx = {
            // Read the index a fresh seal stamps — the session's
            // sending_index, for comparison with the rotated one.
            let mut job = TxCryptoJob::new(inner_packet(0), vec![0u8; 256], 0, stale.clone(), 0);
            job.seal();
            u32::from_le_bytes(job.wire[4..8].try_into().unwrap())
        };
        for _ in 0..8 {
            rotate_session(&mut a, &mut b);
        }

        // The stale handle still seals — the datagram is well-formed
        // under the session it captured (its peer-side slot may be
        // evicted; sealing itself is what the pin covers).
        let counter = stale.reserve_tx_counters(1);
        let mut job = TxCryptoJob::new(inner_packet(1), vec![0u8; 2048], counter, stale, 0);
        job.seal();
        assert!(matches!(job.result, Some(Ok(_))));
        assert_eq!(job.wire[0], 4);
        assert_eq!(
            u32::from_le_bytes(job.wire[4..8].try_into().unwrap()),
            stale_peer_idx,
            "the captured session still seals under its own index"
        );

        // The fresh handle seals under the *new* session — a different
        // sending index — and the peer (post-rotation) opens it.
        let fresh = a.current_session_handle().expect("session is up");
        let counter = fresh.reserve_tx_counters(1);
        let mut job = TxCryptoJob::new(inner_packet(2), vec![0u8; 2048], counter, fresh, 0);
        job.seal();
        let Some(Ok(wire_len)) = job.result else {
            panic!("fresh session seals");
        };
        assert_ne!(
            u32::from_le_bytes(job.wire[4..8].try_into().unwrap()),
            stale_peer_idx,
            "eight rotations moved the outbound session"
        );
        let mut wire = vec![0u8; 2048];
        let res = b.decapsulate(None, &job.wire[..wire_len], &mut wire);
        assert!(
            matches!(
                res,
                crate::noise::TunnResult::WriteToTunnelV4(..)
                    | crate::noise::TunnResult::WriteToTunnelV6(..)
            ),
            "peer opens the fresh-session datagram, got {res:?}"
        );
    }
}
