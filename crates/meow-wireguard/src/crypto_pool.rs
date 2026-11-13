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
//! Why this shape: `std::thread::scope`'s spawn cost (~50 µs per thread
//! per pass) exceeds an entire batch's AEAD time, so per-batch threads
//! lose to serial. Resident workers pay one `mpsc` wakeup (~1–3 µs) per
//! chunk. Dispatch is chunk-based — contiguous `Vec<CryptoJob>` ranges,
//! one message per worker — and each worker's paired result channel
//! returns its chunk in order, so reassembly is positional: chunk
//! boundaries guarantee the original order with no reorder buffer.
//!
//! Worker count `W = min(available_parallelism - 1, 4)`, floor 1 — the
//! `- 1` keeps a core free for the actor's own serial work (verify,
//! post-pass, smoltcp); `4` is where the per-session replay-window
//! mutex and the single consumer stop scaling anyway. `W <= 1` (or a
//! batch of `n <= 2`) skips the pool entirely and runs inline — the
//! serial fallback the spec requires.

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
    /// wire datagram, `wire_len` its bound, and `crypto` the
    /// `Tunn::session_handle_for` result for `receiver_idx`.
    pub fn new(
        buf: Vec<u8>,
        wire_len: usize,
        receiver_idx: u32,
        counter: u64,
        crypto: Option<SessionHandle>,
    ) -> Self {
        Self {
            buf,
            wire_len,
            receiver_idx,
            counter,
            crypto,
            tag: 0,
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

/// The resident worker set. One [`CryptoPool::shared`] instance serves
/// the whole process; `run` serializes callers internally so two actors
/// can never interleave their chunks on a worker's queue.
pub struct CryptoPool {
    /// Job chunk → worker.
    senders: Vec<mpsc::Sender<Vec<CryptoJob>>>,
    /// Worker → finished chunk, one receiver per worker so the caller
    /// drains them in chunk order (the no-reorder guarantee above).
    /// The mutex serializes whole passes: two actors' `run` calls queue
    /// back to back rather than mixing chunks on a worker.
    inner: Mutex<Vec<mpsc::Receiver<Vec<CryptoJob>>>>,
}

impl CryptoPool {
    /// A pool with `workers` resident threads. `workers <= 1` spawns
    /// nothing — `run` then always takes the serial path, which is also
    /// what keeps a single-core or `new(1)` test from paying a dead
    /// thread.
    pub fn new(workers: usize) -> Self {
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        if workers > 1 {
            for _ in 0..workers {
                let (job_tx, job_rx) = mpsc::channel::<Vec<CryptoJob>>();
                let (done_tx, done_rx) = mpsc::channel::<Vec<CryptoJob>>();
                std::thread::Builder::new()
                    .name("wg-crypto".into())
                    .spawn(move || {
                        while let Ok(mut chunk) = job_rx.recv() {
                            for job in &mut chunk {
                                job.decrypt();
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
    /// spawns the workers on the first parallel pass, not at startup:
    /// a process with no WireGuard traffic (or only `n <= 2` batches)
    /// never pays them.
    pub fn shared() -> &'static CryptoPool {
        static POOL: OnceLock<CryptoPool> = OnceLock::new();
        POOL.get_or_init(|| CryptoPool::new(Self::default_workers()))
    }

    /// Run one batch: fill every job's `result`, preserving `jobs`'s
    /// original order. Serial when the batch is too small to pay two
    /// channel hops or when no workers exist; otherwise contiguous
    /// chunks go out one per worker and come back in chunk order — the
    /// positional merge the module docs describe.
    pub fn run(&self, jobs: &mut Vec<CryptoJob>) {
        let n = jobs.len();
        let workers = n.min(self.senders.len());
        if workers <= 1 || n <= 2 {
            for job in jobs.iter_mut() {
                job.decrypt();
            }
            return;
        }

        let rxs = self.inner.lock();

        // Split into `workers` contiguous chunks of ceil(n/workers).
        let per = n.div_ceil(workers);
        let mut chunks: Vec<Vec<CryptoJob>> = Vec::with_capacity(workers);
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
        let mut done: Vec<Option<Vec<CryptoJob>>> = Vec::new();
        done.resize_with(chunks.len(), || None);
        let mut waiting = Vec::with_capacity(chunks.len());
        for (i, chunk) in chunks.into_iter().enumerate() {
            match self.senders[i].send(chunk) {
                Ok(()) => waiting.push(i),
                Err(mpsc::SendError(mut chunk)) => {
                    // Dead worker — run the chunk here rather than lose
                    // its datagrams.
                    for job in &mut chunk {
                        job.decrypt();
                    }
                    done[i] = Some(chunk);
                }
            }
        }
        for i in waiting {
            if let Ok(chunk) = rxs[i].recv() {
                done[i] = Some(chunk);
            }
            // RecvErr ⇒ the worker died mid-pass; the chunk is gone
            // with it — a drop the caller tolerates like a UDP drop.
        }
        for chunk in done.into_iter().flatten() {
            jobs.extend(chunk);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake crypto handle is impossible (the job stores a real
    /// `Option<SessionHandle>`), so these exercise the pool's own
    /// contract — chunking, ordering, the serial fallback — through
    /// `crypto: None` jobs, whose `decrypt` resolves to
    /// `NoCurrentSession` per job without needing a session.
    fn no_session_jobs(n: usize) -> Vec<CryptoJob> {
        (0..n)
            .map(|_| CryptoJob::new(vec![0u8; 64], 64, 0, 0, None))
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
                let mut job = CryptoJob::new(vec![0u8; 64], 64, i, i as u64, None);
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
}
