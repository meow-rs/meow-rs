//! REALITY v2 dial-first orchestration for the VLESS listener.
//!
//! The transport crate owns ClientHello authentication, target-template
//! scanning, sealing and Finished verification.  This module owns the only
//! listener-side resources whose ordering the v2 contract fixes: the H/P/C
//! permits, exactly one early target dial, pre-commit cover ownership and the
//! post-commit target monitor.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use meow_transport::reality_mirror::{
    MirrorCoverReason, MirrorTemplate, MirroredHandshakeCompletion, TargetScanState,
};
use meow_transport::reality_server::{
    relay_cover_with_prefixes, CoverRelayPrefixes, RealityClientHello,
};
use meow_transport::{Stream, TransportError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::vless::RealityRuntime;

const COVER_REASON_COUNT: usize = 15;
const CLOSE_PHASE_COUNT: usize = 8;
const CLOSE_REASON_COUNT: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverReason {
    AuthFailed,
    ProbeSaturated,
    ClientProfile,
    DestProfile,
    Hrr,
    UnsupportedCipher,
    UnsupportedGroup,
    UnsupportedExt,
    RecordLimit,
    Capacity,
    ProbeTimeout,
    DestAlert,
    DestEof,
    LateDestBytes,
    UploadShaping,
}

impl CoverReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AuthFailed => "auth_failed",
            Self::ProbeSaturated => "probe_saturated",
            Self::ClientProfile => "client_profile",
            Self::DestProfile => "dest_profile",
            Self::Hrr => "hrr",
            Self::UnsupportedCipher => "unsupported_cipher",
            Self::UnsupportedGroup => "unsupported_group",
            Self::UnsupportedExt => "unsupported_ext",
            Self::RecordLimit => "record_limit",
            Self::Capacity => "capacity",
            Self::ProbeTimeout => "probe_timeout",
            Self::DestAlert => "dest_alert",
            Self::DestEof => "dest_eof",
            Self::LateDestBytes => "late_dest_bytes",
            Self::UploadShaping => "upload_shaping",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::AuthFailed => 0,
            Self::ProbeSaturated => 1,
            Self::ClientProfile => 2,
            Self::DestProfile => 3,
            Self::Hrr => 4,
            Self::UnsupportedCipher => 5,
            Self::UnsupportedGroup => 6,
            Self::UnsupportedExt => 7,
            Self::RecordLimit => 8,
            Self::Capacity => 9,
            Self::ProbeTimeout => 10,
            Self::DestAlert => 11,
            Self::DestEof => 12,
            Self::LateDestBytes => 13,
            Self::UploadShaping => 14,
        }
    }

    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::AuthFailed,
            1 => Self::ProbeSaturated,
            2 => Self::ClientProfile,
            3 => Self::DestProfile,
            4 => Self::Hrr,
            5 => Self::UnsupportedCipher,
            6 => Self::UnsupportedGroup,
            7 => Self::UnsupportedExt,
            8 => Self::RecordLimit,
            9 => Self::Capacity,
            10 => Self::ProbeTimeout,
            11 => Self::DestAlert,
            12 => Self::DestEof,
            13 => Self::LateDestBytes,
            _ => Self::UploadShaping,
        }
    }
}

impl From<MirrorCoverReason> for CoverReason {
    fn from(value: MirrorCoverReason) -> Self {
        match value {
            MirrorCoverReason::DestProfile => Self::DestProfile,
            MirrorCoverReason::Hrr => Self::Hrr,
            MirrorCoverReason::UnsupportedCipher => Self::UnsupportedCipher,
            MirrorCoverReason::UnsupportedGroup => Self::UnsupportedGroup,
            MirrorCoverReason::UnsupportedExt => Self::UnsupportedExt,
            MirrorCoverReason::RecordLimit => Self::RecordLimit,
            MirrorCoverReason::Capacity => Self::Capacity,
            MirrorCoverReason::DestAlert => Self::DestAlert,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClosePhase {
    Admission,
    ReadAndDial,
    Upload,
    Probe,
    Prepare,
    Emit,
    WaitFinished,
    Cover,
}

impl ClosePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::ReadAndDial => "read_and_dial",
            Self::Upload => "upload",
            Self::Probe => "probe",
            Self::Prepare => "prepare",
            Self::Emit => "emit",
            Self::WaitFinished => "wait_finished",
            Self::Cover => "cover",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Admission => 0,
            Self::ReadAndDial => 1,
            Self::Upload => 2,
            Self::Probe => 3,
            Self::Prepare => 4,
            Self::Emit => 5,
            Self::WaitFinished => 6,
            Self::Cover => 7,
        }
    }

    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Admission,
            1 => Self::ReadAndDial,
            2 => Self::Upload,
            3 => Self::Probe,
            4 => Self::Prepare,
            5 => Self::Emit,
            6 => Self::WaitFinished,
            _ => Self::Cover,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseReason {
    HandshakeSaturated,
    CoverSaturated,
    Resolve,
    Connect,
    ClientLimit,
    ClientIo,
    DestIo,
    Deadline,
    LocalCrypto,
    EmitIo,
    FinishedInvalid,
    DestTail,
    DestEof,
    Canceled,
}

impl CloseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::HandshakeSaturated => "handshake_saturated",
            Self::CoverSaturated => "cover_saturated",
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::ClientLimit => "client_limit",
            Self::ClientIo => "client_io",
            Self::DestIo => "dest_io",
            Self::Deadline => "deadline",
            Self::LocalCrypto => "local_crypto",
            Self::EmitIo => "emit_io",
            Self::FinishedInvalid => "finished_invalid",
            Self::DestTail => "dest_tail",
            Self::DestEof => "dest_eof",
            Self::Canceled => "canceled",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::HandshakeSaturated => 0,
            Self::CoverSaturated => 1,
            Self::Resolve => 2,
            Self::Connect => 3,
            Self::ClientLimit => 4,
            Self::ClientIo => 5,
            Self::DestIo => 6,
            Self::Deadline => 7,
            Self::LocalCrypto => 8,
            Self::EmitIo => 9,
            Self::FinishedInvalid => 10,
            Self::DestTail => 11,
            Self::DestEof => 12,
            Self::Canceled => 13,
        }
    }

    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::HandshakeSaturated,
            1 => Self::CoverSaturated,
            2 => Self::Resolve,
            3 => Self::Connect,
            4 => Self::ClientLimit,
            5 => Self::ClientIo,
            6 => Self::DestIo,
            7 => Self::Deadline,
            8 => Self::LocalCrypto,
            9 => Self::EmitIo,
            10 => Self::FinishedInvalid,
            11 => Self::DestTail,
            12 => Self::DestEof,
            _ => Self::Canceled,
        }
    }
}

pub(crate) struct RealityV2Metrics {
    dial_started: AtomicUsize,
    tcp_connect_started: AtomicUsize,
    probe_started: AtomicUsize,
    committed: AtomicUsize,
    mimic_hit: AtomicUsize,
    cover: [AtomicUsize; COVER_REASON_COUNT],
    close: [AtomicUsize; CLOSE_PHASE_COUNT * CLOSE_REASON_COUNT],
}

impl RealityV2Metrics {
    pub(crate) fn new() -> Self {
        Self {
            dial_started: AtomicUsize::new(0),
            tcp_connect_started: AtomicUsize::new(0),
            probe_started: AtomicUsize::new(0),
            committed: AtomicUsize::new(0),
            mimic_hit: AtomicUsize::new(0),
            cover: std::array::from_fn(|_| AtomicUsize::new(0)),
            close: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }

    fn inc(counter: &AtomicUsize) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_dial_started(&self) {
        Self::inc(&self.dial_started);
    }
    pub(crate) fn inc_tcp_connect_started(&self) {
        Self::inc(&self.tcp_connect_started);
    }
    fn inc_probe_started(&self) {
        Self::inc(&self.probe_started);
    }
    fn inc_committed(&self) {
        Self::inc(&self.committed);
    }
    fn inc_mimic_hit(&self) {
        Self::inc(&self.mimic_hit);
    }
    fn inc_cover(&self, reason: CoverReason) {
        Self::inc(&self.cover[reason.index()]);
    }
    pub(crate) fn inc_close(&self, phase: ClosePhase, reason: CloseReason) {
        Self::inc(&self.close[phase.index() * CLOSE_REASON_COUNT + reason.index()]);
    }

    pub(crate) fn snapshot(
        &self,
        handshake_slots: &Semaphore,
        handshake_max: usize,
        probe_slots: &Semaphore,
        probe_max: usize,
        cover_slots: &Semaphore,
        cover_max: usize,
    ) -> RealityV2MetricsSnapshot {
        let load = |counter: &AtomicUsize| counter.load(Ordering::Relaxed);
        let mut cover_total = BTreeMap::new();
        for index in 0..COVER_REASON_COUNT {
            let value = load(&self.cover[index]);
            if value != 0 {
                cover_total.insert(CoverReason::from_index(index).as_str(), value);
            }
        }
        let mut close_total = BTreeMap::new();
        for phase in 0..CLOSE_PHASE_COUNT {
            for reason in 0..CLOSE_REASON_COUNT {
                let value = load(&self.close[phase * CLOSE_REASON_COUNT + reason]);
                if value != 0 {
                    close_total.insert(
                        (
                            ClosePhase::from_index(phase).as_str(),
                            CloseReason::from_index(reason).as_str(),
                        ),
                        value,
                    );
                }
            }
        }
        RealityV2MetricsSnapshot {
            dial_started_total: load(&self.dial_started),
            tcp_connect_started_total: load(&self.tcp_connect_started),
            probe_started_total: load(&self.probe_started),
            committed_total: load(&self.committed),
            mimic_hit_total: load(&self.mimic_hit),
            cover_total,
            close_total,
            active_handshakes: handshake_max.saturating_sub(handshake_slots.available_permits()),
            active_probes: probe_max.saturating_sub(probe_slots.available_permits()),
            active_covers: cover_max.saturating_sub(cover_slots.available_permits()),
        }
    }
}

/// Test and diagnostics snapshot of the fixed-label v2 counters.  The label
/// sets are closed by the specification; no dynamic peer, target or error
/// strings can appear here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealityV2MetricsSnapshot {
    pub dial_started_total: usize,
    pub tcp_connect_started_total: usize,
    pub probe_started_total: usize,
    pub committed_total: usize,
    pub mimic_hit_total: usize,
    pub cover_total: BTreeMap<&'static str, usize>,
    pub close_total: BTreeMap<(&'static str, &'static str), usize>,
    pub active_handshakes: usize,
    pub active_probes: usize,
    pub active_covers: usize,
}

struct CloseAccountant {
    metrics: Arc<RealityV2Metrics>,
    phase: ClosePhase,
    done: bool,
}

impl CloseAccountant {
    fn new(metrics: Arc<RealityV2Metrics>) -> Self {
        Self {
            metrics,
            phase: ClosePhase::ReadAndDial,
            done: false,
        }
    }

    fn set_phase(&mut self, phase: ClosePhase) {
        self.phase = phase;
    }

    fn close(&mut self, reason: CloseReason) {
        if !self.done {
            self.metrics.inc_close(self.phase, reason);
            self.done = true;
        }
    }

    fn normal_end(&mut self) {
        self.done = true;
    }
}

impl Drop for CloseAccountant {
    fn drop(&mut self) {
        if !self.done {
            self.metrics.inc_close(self.phase, CloseReason::Canceled);
        }
    }
}

/// Result of the listener's exactly-one target dial.  `connect_elapsed` is
/// the application-observed connect poll interval used only to derive the
/// quiescence window; it deliberately excludes any earlier resolution wait.
pub(crate) trait TargetIo: Stream + 'static {
    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

impl TargetIo for TcpStream {
    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // tokio::TcpStream::try_read is gated by cached readiness.  The
        // pre-commit barrier must instead ask the kernel: the scan loop may
        // legitimately have drained the socket and cleared READABLE before a
        // byte arrives inside the synchronous prepare window.  socket2 performs
        // a plain nonblocking recv on the same already-nonblocking fd; there is
        // no tokio userspace read buffer this can race with.
        let socket = socket2::SockRef::from(&*self);
        // SAFETY: an initialized `u8` slice is a valid maybe-uninitialized
        // slice over the same storage.  socket2 documents that recv initializes
        // at most the returned prefix and never reads the input buffer.
        let uninit = unsafe {
            std::slice::from_raw_parts_mut(
                buf.as_mut_ptr().cast::<std::mem::MaybeUninit<u8>>(),
                buf.len(),
            )
        };
        // EINTR returned no bytes, so retry once; a second interruption is
        // target I/O failure rather than a signal-storm retry loop.
        match socket.recv(uninit) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => socket.recv(uninit),
            result => result,
        }
    }
}

pub(crate) struct DialedTarget<T = TcpStream> {
    pub(crate) stream: T,
    pub(crate) connect_elapsed: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DialFirstDialError {
    Resolve,
    Connect,
}

struct CoverHandoff<T> {
    client: Box<dyn Stream>,
    target: T,
    upload_prefix: Vec<u8>,
    download_prefix: Vec<u8>,
    uploaded: u64,
    target_eof: bool,
    reason: CoverReason,
}

async fn handoff_cover<T: TargetIo>(
    reality: &RealityRuntime,
    handoff: CoverHandoff<T>,
    handshake_deadline: Instant,
    handshake_permit: Option<OwnedSemaphorePermit>,
    probe_permit: Option<OwnedSemaphorePermit>,
    accountant: &mut CloseAccountant,
) {
    // Selecting cover enters the CoverPending state before C is acquired;
    // admission failure therefore belongs to the cover phase rather than to
    // whichever probe/read branch selected the fallback.
    accountant.set_phase(ClosePhase::Cover);
    if Instant::now() >= handshake_deadline {
        accountant.close(CloseReason::Deadline);
        return;
    }
    let Ok(cover_permit) = Arc::clone(&reality.cover_slots).try_acquire_owned() else {
        accountant.close(CloseReason::CoverSaturated);
        return;
    };
    reality.metrics.inc_cover(handoff.reason);

    // The handoff is the point where handshake/probe ownership ends.  The
    // cover permit is intentionally retained for the relay lifetime below.
    drop(probe_permit);
    drop(handshake_permit);
    accountant.set_phase(ClosePhase::Cover);

    // Boxed for the same reason as the v1 cover branch: the shared relay owns
    // two 16 KiB direction scratches and must not inflate every dial-first
    // connection future, most of which commit without ever covering.
    let result = Box::pin(relay_cover_with_prefixes(
        handoff.client,
        Box::new(handoff.target),
        CoverRelayPrefixes {
            upload: handoff.upload_prefix,
            download: handoff.download_prefix,
            uploaded: handoff.uploaded,
            download_eof: handoff.target_eof,
        },
        reality.cover_limit,
    ))
    .await;
    drop(cover_permit);
    match result {
        Ok(()) => accountant.normal_end(),
        Err(TransportError::Timeout(_)) => accountant.close(CloseReason::Deadline),
        Err(_) => accountant.close(CloseReason::DestIo),
    }
}

enum UploadWriteOutcome {
    Written,
    HandshakeDeadline,
    ProbeDeadline,
    Io,
}

async fn upload_ch_once(
    target: &mut impl Stream,
    bytes: &[u8],
    probe_deadline: Instant,
    handshake_deadline: Instant,
) -> UploadWriteOutcome {
    let mut write = Box::pin(target.write_all(bytes));
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(handshake_deadline) => UploadWriteOutcome::HandshakeDeadline,
        _ = tokio::time::sleep_until(probe_deadline) => UploadWriteOutcome::ProbeDeadline,
        result = &mut write => {
            match result {
                Ok(()) => UploadWriteOutcome::Written,
                Err(_) => UploadWriteOutcome::Io,
            }
        }
    }
}

enum ProbeScan {
    Template(MirrorTemplate),
    Cover {
        prefix: Vec<u8>,
        reason: CoverReason,
        target_eof: bool,
    },
    Close(CloseReason),
}

fn cover_from_scanner(
    scanner: meow_transport::reality_mirror::TargetFlightScanner<'_>,
    reason: CoverReason,
    target_eof: bool,
) -> ProbeScan {
    ProbeScan::Cover {
        prefix: scanner.into_prefix(),
        reason,
        target_eof,
    }
}

fn freeze_scanner(scanner: meow_transport::reality_mirror::TargetFlightScanner<'_>) -> ProbeScan {
    match scanner.freeze() {
        Ok(template) => ProbeScan::Template(template),
        Err(error) => ProbeScan::Cover {
            prefix: error.into_prefix(),
            reason: CoverReason::DestProfile,
            target_eof: false,
        },
    }
}

async fn scan_target_flight(
    reality: &RealityRuntime,
    context: &meow_transport::reality_server::AuthenticatedMirrorContext,
    target: &mut impl TargetIo,
    quiet: Duration,
    probe_deadline: Instant,
    handshake_deadline: Instant,
) -> ProbeScan {
    let Ok(mut scanner) = reality.server.target_flight_scanner(context) else {
        return ProbeScan::Cover {
            prefix: Vec::new(),
            reason: CoverReason::ClientProfile,
            target_eof: false,
        };
    };
    // The scratch is heap-allocated and dropped before this function returns
    // a template, so prepare never coexists with the read staging allocation.
    let mut scratch = vec![0u8; 4096];
    let mut last_byte_observed = Instant::now();

    loop {
        let state = scanner.state();
        if let TargetScanState::Incompatible(reason) = state {
            drop(scratch);
            return cover_from_scanner(scanner, CoverReason::from(reason), false);
        }
        let window = scanner.read_window();
        if window == 0 {
            drop(scratch);
            return cover_from_scanner(scanner, CoverReason::Capacity, false);
        }
        if state == TargetScanState::Freezable {
            #[cfg(test)]
            tests::observe_scan_event(tests::ScanEvent::Freezable);
        }
        let quiet_at = if state == TargetScanState::Freezable {
            last_byte_observed + quiet
        } else {
            handshake_deadline
        };
        let read_len = window.min(scratch.len());
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(handshake_deadline) => {
                drop(scratch);
                return ProbeScan::Close(CloseReason::Deadline);
            }
            _ = tokio::time::sleep_until(probe_deadline) => {
                drop(scratch);
                return cover_from_scanner(scanner, CoverReason::ProbeTimeout, false);
            }
            read = target.read(&mut scratch[..read_len]), if read_len > 0 => {
                match read {
                    Ok(0) => {
                        drop(scratch);
                        return cover_from_scanner(scanner, CoverReason::DestEof, true);
                    }
                    Ok(n) => {
                        last_byte_observed = Instant::now();
                        let pushed = scanner.push(&scratch[..n]);
                        #[cfg(test)]
                        tests::observe_scan_event(tests::ScanEvent::Bytes(n));
                        match pushed {
                            Ok(TargetScanState::Incompatible(reason)) => {
                                drop(scratch);
                                return cover_from_scanner(scanner, CoverReason::from(reason), false);
                            }
                            Ok(_) => {}
                            Err(_) => {
                                drop(scratch);
                                return ProbeScan::Close(CloseReason::LocalCrypto);
                            }
                        }
                    }
                    Err(_) => {
                        drop(scratch);
                        return ProbeScan::Close(CloseReason::DestIo);
                    }
                }
            }
            _ = tokio::time::sleep_until(quiet_at), if state == TargetScanState::Freezable => {
                drop(scratch);
                return freeze_scanner(scanner);
            }
        }
    }
}

enum PostCommitOutcome {
    Established(Box<dyn Stream>),
    Close {
        phase: ClosePhase,
        reason: CloseReason,
    },
}

fn monitor_close_reason(read: &io::Result<usize>) -> CloseReason {
    match read {
        Ok(0) => CloseReason::DestEof,
        Ok(_) => CloseReason::DestTail,
        Err(_) => CloseReason::DestIo,
    }
}

fn finish_close_reason(error: &TransportError) -> CloseReason {
    match error {
        TransportError::Io(_) => CloseReason::ClientIo,
        TransportError::Timeout(_) => CloseReason::Deadline,
        TransportError::Crypto(_) => CloseReason::LocalCrypto,
        _ => CloseReason::FinishedInvalid,
    }
}

async fn drive_post_commit<T: TargetIo>(
    mut target: T,
    mut client: Box<dyn Stream>,
    wire: Vec<u8>,
    completion: MirroredHandshakeCompletion,
    handshake_deadline: Instant,
    commit_at: Instant,
) -> PostCommitOutcome {
    let emit_deadline = handshake_deadline.min(commit_at + Duration::from_secs(3));
    let mut tail = [0u8; 1];
    let mut monitor = Box::pin(target.read(&mut tail));
    let mut emit = Box::pin(async {
        client.write_all(&wire).await?;
        client.flush().await
    });

    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(handshake_deadline) => {
            return PostCommitOutcome::Close { phase: ClosePhase::Emit, reason: CloseReason::Deadline };
        }
        _ = tokio::time::sleep_until(emit_deadline) => {
            return PostCommitOutcome::Close { phase: ClosePhase::Emit, reason: CloseReason::Deadline };
        }
        read = &mut monitor => {
            return PostCommitOutcome::Close { phase: ClosePhase::Emit, reason: monitor_close_reason(&read) };
        }
        result = &mut emit => {
            if result.is_err() {
                return PostCommitOutcome::Close { phase: ClosePhase::Emit, reason: CloseReason::EmitIo };
            }
        }
    }
    drop(emit);
    drop(wire);

    let emit_done = Instant::now();
    let finish_deadline = handshake_deadline.min(emit_done + Duration::from_secs(5));
    let mut finish = Box::pin(completion.finish(client));
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(handshake_deadline) => {
            PostCommitOutcome::Close { phase: ClosePhase::WaitFinished, reason: CloseReason::Deadline }
        }
        _ = tokio::time::sleep_until(finish_deadline) => {
            PostCommitOutcome::Close { phase: ClosePhase::WaitFinished, reason: CloseReason::Deadline }
        }
        read = &mut monitor => {
            PostCommitOutcome::Close { phase: ClosePhase::WaitFinished, reason: monitor_close_reason(&read) }
        }
        result = &mut finish => {
            match result {
                Ok(stream) => {
                    drop(finish);
                    drop(monitor);
                    drop(target);
                    PostCommitOutcome::Established(stream)
                }
                Err(error) => {
                    PostCommitOutcome::Close {
                        phase: ClosePhase::WaitFinished,
                        reason: finish_close_reason(&error),
                    }
                }
            }
        }
    }
}

fn quiet_window(connect_elapsed: Duration, min_ms: u64, max_ms: u64) -> Duration {
    let half_floor_ms = u64::try_from(connect_elapsed.as_millis() / 2).unwrap_or(u64::MAX);
    Duration::from_millis(half_floor_ms.clamp(min_ms, max_ms))
}

fn preflight_close_reason(error: &TransportError) -> CloseReason {
    match error {
        TransportError::ResourceLimit(_) => CloseReason::ClientLimit,
        TransportError::Timeout(_) => CloseReason::Deadline,
        _ => CloseReason::ClientIo,
    }
}

/// Drive the complete dial-first admission state machine.  On success the
/// returned stream is the transport's original client stream wrapped in the
/// mirrored REALITY application keys; every other terminal path either
/// enters the shared cover relay or closes without emitting local TLS.
pub(crate) async fn run_dial_first<D, T>(
    reality: &RealityRuntime,
    client: Box<dyn Stream>,
    handshake_deadline: Instant,
    handshake_permit: Option<OwnedSemaphorePermit>,
    dial: D,
) -> Option<Box<dyn Stream>>
where
    D: Future<Output = Result<DialedTarget<T>, DialFirstDialError>>,
    T: TargetIo,
{
    let metrics = Arc::clone(&reality.metrics);
    let mut accountant = CloseAccountant::new(metrics);
    if Instant::now() >= handshake_deadline {
        accountant.close(CloseReason::Deadline);
        return None;
    }
    let dial_begin = Instant::now();
    let dial_deadline = handshake_deadline.min(dial_begin + Duration::from_secs(3));

    let mut preflight = Box::pin(reality.server.verify_client_hello(client));
    let mut dial = Box::pin(dial);
    let mut preflight_result = None;
    let mut dial_result = None;

    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(handshake_deadline) => {
                accountant.close(CloseReason::Deadline);
                return None;
            }
            _ = tokio::time::sleep_until(dial_deadline), if dial_result.is_none() => {
                accountant.close(CloseReason::Deadline);
                return None;
            }
            result = &mut dial, if dial_result.is_none() => {
                match result {
                    Ok(target) => dial_result = Some(target),
                    Err(DialFirstDialError::Resolve) => {
                        accountant.close(CloseReason::Resolve);
                        return None;
                    }
                    Err(DialFirstDialError::Connect) => {
                        accountant.close(CloseReason::Connect);
                        return None;
                    }
                }
            }
            result = &mut preflight, if preflight_result.is_none() => {
                match result {
                    Ok(classified) => preflight_result = Some(classified),
                    Err(error) => {
                        accountant.close(preflight_close_reason(&error));
                        return None;
                    }
                }
            }
        }
        if preflight_result.is_some() && dial_result.is_some() {
            break;
        }
    }

    let mut target = dial_result.expect("read-and-dial join has target");
    let classified = preflight_result.expect("read-and-dial join has preflight");
    let quiet = quiet_window(
        target.connect_elapsed,
        reality.mimic.quiescence_min_ms,
        reality.mimic.quiescence_max_ms,
    );

    let (client, hello) = match classified {
        RealityClientHello::Cover(relay) => {
            let (client, upload_prefix) = relay.into_parts();
            handoff_cover(
                reality,
                CoverHandoff {
                    client,
                    target: target.stream,
                    upload_prefix,
                    download_prefix: Vec::new(),
                    uploaded: 0,
                    target_eof: false,
                    reason: CoverReason::AuthFailed,
                },
                handshake_deadline,
                handshake_permit,
                None,
                &mut accountant,
            )
            .await;
            return None;
        }
        RealityClientHello::Verified { stream, hello } => (stream, hello),
    };

    let upload = (*hello).into_mirror_upload();
    let ch_len = upload.ch_wire().len();
    let mirror_profile = upload.context().mirror_profile();
    let upload_shaping_exceeded = reality.cover_limit.upload_bytes_per_second != 0
        && u64::try_from(ch_len).unwrap_or(u64::MAX) > reality.cover_limit.upload_exempt_bytes;
    if mirror_profile.is_err() || upload_shaping_exceeded {
        let reason = if upload_shaping_exceeded {
            CoverReason::UploadShaping
        } else {
            CoverReason::ClientProfile
        };
        let (context, wire) = upload.finish_upload();
        drop(context);
        handoff_cover(
            reality,
            CoverHandoff {
                client,
                target: target.stream,
                upload_prefix: wire,
                download_prefix: Vec::new(),
                uploaded: 0,
                target_eof: false,
                reason,
            },
            handshake_deadline,
            handshake_permit,
            None,
            &mut accountant,
        )
        .await;
        return None;
    }

    let Ok(probe_permit) = Arc::clone(&reality.probe_slots).try_acquire_owned() else {
        let (context, wire) = upload.finish_upload();
        drop(context);
        handoff_cover(
            reality,
            CoverHandoff {
                client,
                target: target.stream,
                upload_prefix: wire,
                download_prefix: Vec::new(),
                uploaded: 0,
                target_eof: false,
                reason: CoverReason::ProbeSaturated,
            },
            handshake_deadline,
            handshake_permit,
            None,
            &mut accountant,
        )
        .await;
        return None;
    };

    accountant.set_phase(ClosePhase::Upload);
    let probe_start = Instant::now();
    reality.metrics.inc_probe_started();
    let probe_deadline = handshake_deadline.min(probe_start + reality.mimic.probe_timeout());
    let write_outcome = upload_ch_once(
        &mut target.stream,
        upload.ch_wire(),
        probe_deadline,
        handshake_deadline,
    )
    .await;
    match write_outcome {
        UploadWriteOutcome::Written => {}
        UploadWriteOutcome::HandshakeDeadline | UploadWriteOutcome::ProbeDeadline => {
            accountant.close(CloseReason::Deadline);
            return None;
        }
        UploadWriteOutcome::Io => {
            accountant.close(CloseReason::DestIo);
            return None;
        }
    }
    let uploaded = u64::try_from(ch_len).unwrap_or(u64::MAX);
    let (context, wire) = upload.finish_upload();
    drop(wire);

    accountant.set_phase(ClosePhase::Probe);
    let scan = scan_target_flight(
        reality,
        &context,
        &mut target.stream,
        quiet,
        probe_deadline,
        handshake_deadline,
    )
    .await;
    let template = match scan {
        ProbeScan::Template(template) => template,
        ProbeScan::Cover {
            prefix,
            reason,
            target_eof,
        } => {
            handoff_cover(
                reality,
                CoverHandoff {
                    client,
                    target: target.stream,
                    upload_prefix: Vec::new(),
                    download_prefix: prefix,
                    uploaded,
                    target_eof,
                    reason,
                },
                handshake_deadline,
                handshake_permit,
                Some(probe_permit),
                &mut accountant,
            )
            .await;
            return None;
        }
        ProbeScan::Close(reason) => {
            accountant.close(reason);
            return None;
        }
    };

    accountant.set_phase(ClosePhase::Prepare);
    let prepared = match reality.server.prepare_mirrored_upload(context, template) {
        Ok(prepared) => prepared,
        Err(error) => {
            // The error object owns the same prefix allocation.  Recover it
            // before closing so ownership remains explicit even though local
            // invariant/crypto failure is never a peer-incompatibility cover.
            drop(error.into_target_prefix());
            accountant.close(CloseReason::LocalCrypto);
            return None;
        }
    };

    let now = Instant::now();
    if now >= handshake_deadline {
        accountant.close(CloseReason::Deadline);
        return None;
    }
    if now >= probe_deadline {
        handoff_cover(
            reality,
            CoverHandoff {
                client,
                target: target.stream,
                upload_prefix: Vec::new(),
                download_prefix: prepared.into_cover_prefix(),
                uploaded,
                target_eof: false,
                reason: CoverReason::ProbeTimeout,
            },
            handshake_deadline,
            handshake_permit,
            Some(probe_permit),
            &mut accountant,
        )
        .await;
        return None;
    }

    #[cfg(test)]
    tests::invoke_pre_commit_hook();

    let mut tail = [0u8; 1];
    match target.stream.try_read(&mut tail) {
        Ok(0) => {
            handoff_cover(
                reality,
                CoverHandoff {
                    client,
                    target: target.stream,
                    upload_prefix: Vec::new(),
                    download_prefix: prepared.into_cover_prefix(),
                    uploaded,
                    target_eof: true,
                    reason: CoverReason::DestEof,
                },
                handshake_deadline,
                handshake_permit,
                Some(probe_permit),
                &mut accountant,
            )
            .await;
            return None;
        }
        Ok(_) => {
            let mut prefix = prepared.into_cover_prefix();
            prefix.push(tail[0]);
            handoff_cover(
                reality,
                CoverHandoff {
                    client,
                    target: target.stream,
                    upload_prefix: Vec::new(),
                    download_prefix: prefix,
                    uploaded,
                    target_eof: false,
                    reason: CoverReason::LateDestBytes,
                },
                handshake_deadline,
                handshake_permit,
                Some(probe_permit),
                &mut accountant,
            )
            .await;
            return None;
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => {
            accountant.close(CloseReason::DestIo);
            return None;
        }
    }

    let committed = prepared.commit();
    reality.metrics.inc_committed();
    let commit_at = Instant::now();
    let (wire, completion) = committed.into_wire_and_completion();
    accountant.set_phase(ClosePhase::Emit);
    let outcome = drive_post_commit(
        target.stream,
        client,
        wire,
        completion,
        handshake_deadline,
        commit_at,
    )
    .await;
    match outcome {
        PostCommitOutcome::Close { phase, reason } => {
            accountant.set_phase(phase);
            accountant.close(reason);
            None
        }
        PostCommitOutcome::Established(stream) => {
            drop(probe_permit);
            drop(handshake_permit);
            reality.metrics.inc_mimic_hit();
            accountant.normal_end();
            Some(stream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_transport::reality_server::{CoverBandwidthLimit, RealityServerConfig};
    use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer};
    use meow_transport::Transport;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::time::advance;

    #[derive(Clone, Copy, Debug)]
    pub(super) enum ScanEvent {
        #[allow(
            dead_code,
            reason = "read only by the cfg(unix) real-loopback scan-sync tests"
        )]
        Bytes(usize),
        Freezable,
    }

    type ScanObserverCell = std::cell::RefCell<Option<Box<dyn FnMut(ScanEvent)>>>;

    thread_local! {
        static PRE_COMMIT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        static SCAN_OBSERVER: ScanObserverCell = const { std::cell::RefCell::new(None) };
    }

    pub(super) fn invoke_pre_commit_hook() {
        PRE_COMMIT_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
    }

    pub(super) fn observe_scan_event(event: ScanEvent) {
        SCAN_OBSERVER.with(|observer| {
            if let Some(observer) = observer.borrow_mut().as_mut() {
                observer(event);
            }
        });
    }

    #[cfg(unix)]
    fn wait_target_readiness(fd: std::os::fd::RawFd) {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let rc = unsafe { libc::poll(&mut pollfd, 1, 1_000) };
            if rc > 0 {
                assert_ne!(
                    pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR),
                    0,
                    "target readability poll returned unrelated events: {}",
                    pollfd.revents
                );
                return;
            }
            if rc == 0 {
                panic!("timed out waiting for loopback target readability");
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                panic!("target readability poll failed: {error}");
            }
        }
    }

    const PRIVATE: [u8; 32] = [0x42; 32];
    const SHORT: [u8; 8] = [1, 2, 3, 4, 0, 0, 0, 0];

    fn public_key() -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(PRIVATE);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    }

    fn runtime() -> Arc<RealityRuntime> {
        let mimic = crate::vless::VlessRealityMimicSpec {
            quiescence_max_ms: 150,
            ..Default::default()
        };
        Arc::new(RealityRuntime {
            server: meow_transport::reality_server::RealityServer::new(&RealityServerConfig {
                private_key: PRIVATE,
                short_ids: vec![SHORT],
                server_names: ["localhost".into()].into(),
                max_time_difference: Some(Duration::ZERO),
                now: None,
            })
            .unwrap(),
            dest_host: "target.invalid".into(),
            dest_port: 443,
            cover_limit: CoverBandwidthLimit {
                upload_bytes_per_second: 0,
                upload_exempt_bytes: 0,
                download_bytes_per_second: 0,
                download_exempt_bytes: 0,
                burst_bytes: 0,
            },
            handshake_slots: Arc::new(Semaphore::new(256)),
            probe_slots: Arc::new(Semaphore::new(64)),
            cover_slots: Arc::new(Semaphore::new(64)),
            mimic,
            metrics: Arc::new(RealityV2Metrics::new()),
        })
    }

    fn snapshot(runtime: &RealityRuntime) -> RealityV2MetricsSnapshot {
        runtime.metrics.snapshot(
            &runtime.handshake_slots,
            256,
            &runtime.probe_slots,
            64,
            &runtime.cover_slots,
            64,
        )
    }

    async fn yields(times: usize) {
        for _ in 0..times {
            tokio::task::yield_now().await;
        }
    }

    #[derive(Clone, Copy)]
    enum TryStep {
        Byte(u8),
        Eof,
        WouldBlock,
    }

    struct MockTarget {
        inner: DuplexStream,
        steps: Arc<Mutex<VecDeque<TryStep>>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
        writes: Arc<Mutex<Vec<u8>>>,
        max_write_chunk: usize,
        zero_writes: bool,
        write_calls: Arc<AtomicUsize>,
    }

    impl Drop for MockTarget {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Relaxed);
        }
    }

    impl AsyncRead for MockTarget {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockTarget {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.zero_writes {
                self.write_calls.fetch_add(1, Ordering::Relaxed);
                return Poll::Ready(Ok(0));
            }
            let limited = &buf[..buf.len().min(self.max_write_chunk)];
            let result = Pin::new(&mut self.inner).poll_write(cx, limited);
            if let Poll::Ready(Ok(n)) = result {
                self.write_calls.fetch_add(1, Ordering::Relaxed);
                self.writes.lock().unwrap().extend_from_slice(&limited[..n]);
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl TargetIo for MockTarget {
        fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(TryStep::WouldBlock)
            {
                TryStep::Byte(byte) => {
                    buf[0] = byte;
                    Ok(1)
                }
                TryStep::Eof => Ok(0),
                TryStep::WouldBlock => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        }
    }

    struct ScriptedClient {
        inner: DuplexStream,
        input: VecDeque<u8>,
        writes: Arc<Mutex<Vec<u8>>>,
        fail_after_first_write_bytes: Option<usize>,
        write_call: usize,
    }

    impl AsyncRead for ScriptedClient {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.input.is_empty() {
                let n = buf.remaining().min(self.input.len());
                let bytes: Vec<u8> = self.input.drain(..n).collect();
                buf.put_slice(&bytes);
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ScriptedClient {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut write_buf = buf;
            if let Some(limit) = self.fail_after_first_write_bytes {
                if self.write_call != 0 {
                    return Poll::Ready(Ok(0));
                }
                self.write_call += 1;
                write_buf = &buf[..buf.len().min(limit)];
            }
            let result = Pin::new(&mut self.inner).poll_write(cx, write_buf);
            if let Poll::Ready(Ok(n)) = result {
                self.writes
                    .lock()
                    .unwrap()
                    .extend_from_slice(&write_buf[..n]);
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn mock_target(
        steps: Vec<TryStep>,
    ) -> (MockTarget, DuplexStream, Arc<std::sync::atomic::AtomicBool>) {
        mock_target_with_log(steps, Arc::new(Mutex::new(Vec::new())))
    }

    fn mock_target_with_log(
        steps: Vec<TryStep>,
        writes: Arc<Mutex<Vec<u8>>>,
    ) -> (MockTarget, DuplexStream, Arc<std::sync::atomic::AtomicBool>) {
        mock_target_shaped(steps, writes, usize::MAX, false)
    }

    fn mock_target_shaped(
        steps: Vec<TryStep>,
        writes: Arc<Mutex<Vec<u8>>>,
        max_write_chunk: usize,
        zero_writes: bool,
    ) -> (MockTarget, DuplexStream, Arc<std::sync::atomic::AtomicBool>) {
        let (target, peer, dropped, _) =
            mock_target_shaped_with_counter(steps, writes, max_write_chunk, zero_writes);
        (target, peer, dropped)
    }

    #[allow(clippy::type_complexity)]
    fn mock_target_shaped_with_counter(
        steps: Vec<TryStep>,
        writes: Arc<Mutex<Vec<u8>>>,
        max_write_chunk: usize,
        zero_writes: bool,
    ) -> (
        MockTarget,
        DuplexStream,
        Arc<std::sync::atomic::AtomicBool>,
        Arc<AtomicUsize>,
    ) {
        let (inner, peer) = tokio::io::duplex(256 * 1024);
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let write_calls = Arc::new(AtomicUsize::new(0));
        (
            MockTarget {
                inner,
                steps: Arc::new(Mutex::new(steps.into())),
                dropped: Arc::clone(&dropped),
                writes,
                max_write_chunk,
                zero_writes,
                write_calls: Arc::clone(&write_calls),
            },
            peer,
            dropped,
            write_calls,
        )
    }

    fn scripted_client(ch: &[u8]) -> (ScriptedClient, DuplexStream, Arc<Mutex<Vec<u8>>>) {
        scripted_client_with_capacity(ch, 256 * 1024)
    }

    fn scripted_client_with_capacity(
        ch: &[u8],
        capacity: usize,
    ) -> (ScriptedClient, DuplexStream, Arc<Mutex<Vec<u8>>>) {
        let (inner, peer) = tokio::io::duplex(capacity);
        let writes = Arc::new(Mutex::new(Vec::new()));
        (
            ScriptedClient {
                inner,
                input: ch.iter().copied().collect(),
                writes: Arc::clone(&writes),
                fail_after_first_write_bytes: None,
                write_call: 0,
            },
            peer,
            writes,
        )
    }

    fn scripted_client_failing_after_first_write(
        ch: &[u8],
        bytes: usize,
    ) -> (ScriptedClient, DuplexStream, Arc<Mutex<Vec<u8>>>) {
        let (mut client, peer, writes) = scripted_client(ch);
        client.fail_after_first_write_bytes = Some(bytes);
        (client, peer, writes)
    }

    async fn capture_client_hello() -> Vec<u8> {
        let (client_end, mut server_end) = tokio::io::duplex(128 * 1024);
        let tls = TlsConfig {
            reality: Some(RealityConfig {
                public_key: public_key(),
                short_id: SHORT,
                support_x25519_mlkem768: false,
                protocol_clock: None,
            }),
            ..TlsConfig::new("localhost")
        };
        let layer = TlsLayer::new(&tls).unwrap();
        let task = tokio::spawn(async move { layer.connect(Box::new(client_end)).await });
        let wire = read_record(&mut server_end).await;
        task.abort();
        wire
    }

    async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut head = [0u8; 5];
        stream.read_exact(&mut head).await.unwrap();
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.unwrap();
        let mut wire = head.to_vec();
        wire.extend_from_slice(&body);
        wire
    }

    fn ext(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn flight(session_id: &[u8; 32]) -> Vec<u8> {
        let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
        let share = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let mut key_share_body = Vec::new();
        key_share_body.extend_from_slice(&0x001du16.to_be_bytes());
        key_share_body.extend_from_slice(&(share.len() as u16).to_be_bytes());
        key_share_body.extend_from_slice(&share);
        let mut exts = ext(0x002b, &0x0304u16.to_be_bytes());
        exts.extend_from_slice(&ext(0x0033, &key_share_body));
        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[0x66; 32]);
        body.push(32);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut sh = vec![2];
        sh.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        sh.extend_from_slice(&body);
        let mut out = Vec::new();
        out.extend_from_slice(&[0x16, 3, 3]);
        out.extend_from_slice(&(sh.len() as u16).to_be_bytes());
        out.extend_from_slice(&sh);
        out.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
        for len in [25u16, 3217, 281, 69] {
            out.extend_from_slice(&[0x17, 3, 3]);
            out.extend_from_slice(&len.to_be_bytes());
            out.resize(out.len() + usize::from(len), 0x5a);
        }
        out
    }

    fn extra_record() -> Vec<u8> {
        let mut out = vec![0x17, 3, 3, 0, 18];
        out.resize(out.len() + 18, 0x33);
        out
    }

    fn session_id(ch: &[u8]) -> [u8; 32] {
        assert_eq!(ch[5], 1, "first handshake is ClientHello");
        assert_eq!(ch[5 + 38], 32);
        ch[5 + 39..5 + 71].try_into().unwrap()
    }

    fn spawn_machine<T: TargetIo>(
        runtime: &Arc<RealityRuntime>,
        client: ScriptedClient,
        target: T,
        deadline: Instant,
    ) -> tokio::task::JoinHandle<Option<Box<dyn Stream>>> {
        let dial = async move {
            Ok::<_, DialFirstDialError>(DialedTarget {
                stream: target,
                connect_elapsed: Duration::from_millis(200),
            })
        };
        spawn_machine_with_dial(runtime, client, deadline, dial)
    }

    fn spawn_machine_with_dial<T, D>(
        runtime: &Arc<RealityRuntime>,
        client: ScriptedClient,
        deadline: Instant,
        dial: D,
    ) -> tokio::task::JoinHandle<Option<Box<dyn Stream>>>
    where
        T: TargetIo,
        D: std::future::Future<Output = Result<DialedTarget<T>, DialFirstDialError>>
            + Send
            + 'static,
    {
        let permit = Arc::clone(&runtime.handshake_slots)
            .try_acquire_owned()
            .unwrap();
        let runtime = Arc::clone(runtime);
        tokio::spawn(async move {
            run_dial_first(
                &runtime,
                Box::new(client) as Box<dyn Stream>,
                deadline,
                Some(permit),
                dial,
            )
            .await
        })
    }

    async fn upload_and_write_flight<S: AsyncRead + AsyncWrite + Unpin>(
        ch: &[u8],
        target_peer: &mut S,
    ) -> Vec<u8> {
        let uploaded = read_record(target_peer).await;
        assert_eq!(
            uploaded, ch,
            "probe uploads the exact authenticated CH once"
        );
        let sid = session_id(&uploaded);
        let flight = flight(&sid);
        target_peer.write_all(&flight).await.unwrap();
        target_peer.flush().await.unwrap();
        flight
    }

    #[cfg(unix)]
    async fn real_target_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = TcpStream::connect(addr).await.unwrap();
        let (target, _) = listener.accept().await.unwrap();
        (target, peer)
    }

    #[cfg(unix)]
    fn inhibit_paused_time_auto_advance(
    ) -> (std::sync::mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let task = tokio::task::spawn_blocking(move || {
            let _ = rx.recv();
        });
        (tx, task)
    }

    #[cfg(unix)]
    async fn real_precommit_case(eof: bool) -> (RealityV2MetricsSnapshot, Vec<u8>, Vec<u8>) {
        // A paused current_thread runtime otherwise auto-advances to the
        // probe deadline while the test is merely parked on real loopback IO.
        // A parked blocking task is tokio's supported inhibitor; dropping the
        // sender releases it when the case ends.
        let (inhibit_tx, inhibit_task) = inhibit_paused_time_auto_advance();
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, mut client_peer, writes) = scripted_client(&ch);
        let (target, mut target_peer) = real_target_pair().await;
        let target_fd = {
            use std::os::fd::AsRawFd;
            target.as_raw_fd()
        };
        let (scan_tx, mut scan_rx) = tokio::sync::mpsc::unbounded_channel();
        SCAN_OBSERVER.with(|observer| {
            *observer.borrow_mut() = Some(Box::new(move |event| {
                let _ = scan_tx.send(event);
            }));
        });
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        let flight = upload_and_write_flight(&ch, &mut target_peer).await;

        // Real loopback IO has no deterministic userspace flush boundary.
        // Wait for the scan loop's own byte-consumption events and for its
        // Freezable state; only then can opening the quiet window not race
        // undelivered or unconsumed flight bytes.
        let mut consumed = 0usize;
        let mut freezable = false;
        let mut scan_events = Vec::new();
        while !(freezable && consumed == flight.len()) {
            let event = scan_rx.recv().await.unwrap();
            scan_events.push(event);
            match event {
                ScanEvent::Bytes(n) => consumed += n,
                ScanEvent::Freezable => freezable = true,
            }
            assert!(
                consumed <= flight.len(),
                "scanner consumed bytes no test wrote"
            );
        }

        let target_peer = Arc::new(target_peer);
        let hook_peer = Arc::clone(&target_peer);
        PRE_COMMIT_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                if eof {
                    socket2::SockRef::from(&*hook_peer)
                        .shutdown(std::net::Shutdown::Write)
                        .unwrap();
                } else {
                    hook_peer.try_write(&[0x77]).unwrap();
                }
                wait_target_readiness(target_fd);
            }));
        });
        advance(Duration::from_millis(100)).await;

        // Reading the recovered prefix from the client socket is the
        // synchronization point for handoff: cover accounting is incremented
        // before the relay can produce these bytes.
        let expected_len = flight.len() + usize::from(!eof);
        let mut got = vec![0u8; expected_len];
        let read_result = client_peer.read_exact(&mut got).await;
        let snap = snapshot(&runtime);
        assert!(
            read_result.is_ok(),
            "cover prefix read failed: {read_result:?}; consumed={consumed} events={scan_events:?} snap={snap:?}"
        );
        let written = writes.lock().unwrap().clone();
        machine.abort();
        SCAN_OBSERVER.with(|observer| observer.borrow_mut().take());
        drop(target_peer);
        drop(inhibit_tx);
        let _ = inhibit_task.await;
        (snap, written, flight)
    }

    // These two tests exercise the kernel-level pre-commit recv barrier.
    // Their synchronization hook uses poll(2) on a raw fd, so they are
    // honestly Unix-only rather than silently weakening the barrier elsewhere.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn t3_real_loopback_raw_recv_observes_prepare_window_tail_byte() {
        let (snap, written, flight) = real_precommit_case(false).await;
        let mut expected = flight;
        expected.push(0x77);
        assert_eq!(
            snap.cover_total.get("late_dest_bytes"),
            Some(&1),
            "snap={snap:?}"
        );
        assert_eq!(snap.committed_total, 0);
        assert_eq!(written, expected);
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn t3_real_loopback_raw_recv_observes_prepare_window_eof() {
        let (snap, written, flight) = real_precommit_case(true).await;
        assert_eq!(snap.cover_total.get("dest_eof"), Some(&1), "snap={snap:?}");
        assert_eq!(snap.committed_total, 0);
        assert_eq!(written, flight);
    }

    #[tokio::test(start_paused = true)]
    async fn t3_delayed_dial_can_finish_while_fragmented_ch_is_incomplete() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, mut client_peer, _client_writes) = scripted_client(&[]);
        let target_writes = Arc::new(Mutex::new(Vec::new()));
        let (target, mut target_peer, _dropped) =
            mock_target_with_log(vec![], Arc::clone(&target_writes));
        let dial_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dial_done_in_dial = Arc::clone(&dial_done);
        let dial = async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            dial_done_in_dial.store(true, Ordering::Relaxed);
            Ok::<_, DialFirstDialError>(DialedTarget {
                stream: target,
                connect_elapsed: Duration::from_millis(80),
            })
        };
        let machine = spawn_machine_with_dial(
            &runtime,
            client,
            Instant::now() + Duration::from_secs(5),
            dial,
        );

        yields(5).await;
        let split = ch.len() / 2;
        client_peer.write_all(&ch[..split]).await.unwrap();
        advance(Duration::from_millis(90)).await;
        yields(10).await;
        assert!(
            dial_done.load(Ordering::Relaxed),
            "fixed-target dial must complete concurrently with incomplete client preflight"
        );
        assert!(
            target_writes.lock().unwrap().is_empty(),
            "no CH prefix may be uploaded before the complete authenticated CH"
        );

        client_peer.write_all(&ch[split..]).await.unwrap();
        let uploaded = read_record(&mut target_peer).await;
        assert_eq!(uploaded, ch);
        assert_eq!(snapshot(&runtime).probe_started_total, 1);
        machine.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn t3_upload_partial_writes_continue_remaining_ch_exactly_once() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, _writes) = scripted_client(&ch);
        let target_writes = Arc::new(Mutex::new(Vec::new()));
        let (target, mut target_peer, _dropped, write_calls) =
            mock_target_shaped_with_counter(vec![], Arc::clone(&target_writes), 128, false);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        let uploaded = read_record(&mut target_peer).await;
        assert_eq!(
            uploaded, ch,
            "continued writes preserve exact CH bytes and order"
        );
        assert!(
            write_calls.load(Ordering::Relaxed) > 1,
            "test must exercise multiple partial target writes"
        );
        assert_eq!(snapshot(&runtime).probe_started_total, 1);
        machine.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn t3_upload_zero_write_closes_without_cover_or_commit() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, _writes) = scripted_client(&ch);
        let target_writes = Arc::new(Mutex::new(Vec::new()));
        let (target, _target_peer, dropped, write_calls) =
            mock_target_shaped_with_counter(vec![], target_writes, usize::MAX, true);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        yields(30).await;
        machine.await.unwrap();
        let snap = snapshot(&runtime);
        assert_eq!(write_calls.load(Ordering::Relaxed), 1);
        assert_eq!(snap.probe_started_total, 1);
        assert_eq!(snap.close_total.get(&("upload", "dest_io")), Some(&1));
        assert_eq!(snap.cover_total.values().sum::<usize>(), 0);
        assert_eq!(snap.committed_total, 0);
        assert!(dropped.load(Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn t3_new_bytes_reset_quiet_and_no_client_write_before_t_last_plus_q() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, writes) = scripted_client(&ch);
        let target_writes = Arc::new(Mutex::new(Vec::new()));
        let (target, mut target_peer, _dropped) =
            mock_target_with_log(vec![], Arc::clone(&target_writes));
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        let _flight = upload_and_write_flight(&ch, &mut target_peer).await;
        target_writes.lock().unwrap().clear();
        yields(10).await;

        // q = floor(200ms/2) = 100ms.  Half of that interval elapses after
        // the first complete flight; there must be no commit or client write.
        advance(Duration::from_millis(50)).await;
        yields(10).await;
        assert_eq!(snapshot(&runtime).committed_total, 0);
        assert!(writes.lock().unwrap().is_empty());
        assert!(
            target_writes.lock().unwrap().is_empty(),
            "zero target writes before t_last+q"
        );

        // A complete extra application record is target input ready long
        // before the original quiet deadline.  It must be consumed first and
        // becomes the new t_last; the old quiet deadline must not fire.
        target_peer.write_all(&extra_record()).await.unwrap();
        target_peer.flush().await.unwrap();
        yields(10).await;
        advance(Duration::from_millis(99)).await;
        yields(10).await;
        assert_eq!(
            snapshot(&runtime).committed_total,
            0,
            "the quiet baseline from the earlier flight must have been reset"
        );
        assert!(writes.lock().unwrap().is_empty());
        assert!(
            target_writes.lock().unwrap().is_empty(),
            "zero target writes before reset t_last+q"
        );

        advance(Duration::from_millis(1)).await;
        yields(20).await;
        let snap = snapshot(&runtime);
        assert_eq!(
            snap.committed_total, 1,
            "commit occurs at the reset t_last+q"
        );
        assert!(!writes.lock().unwrap().is_empty(), "emit follows commit");
        machine.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn t3_ready_target_bytes_beat_quiet_at_equal_instant() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, writes) = scripted_client(&ch);
        let (target, mut target_peer, _dropped) = mock_target(vec![]);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        let _flight = upload_and_write_flight(&ch, &mut target_peer).await;
        yields(10).await;

        // Queue a complete extra record while the machine is not scheduled,
        // then advance exactly to the original quiet deadline.  Readiness and
        // quiet are therefore observable in the same poll; the read branch's
        // priority must consume the bytes instead of freezing.
        target_peer.write_all(&extra_record()).await.unwrap();
        target_peer.flush().await.unwrap();
        advance(Duration::from_millis(100)).await;
        yields(20).await;
        assert_eq!(snapshot(&runtime).committed_total, 0);
        assert!(writes.lock().unwrap().is_empty());

        // The reset baseline starts when those bytes are consumed at t=100ms,
        // so the freeze happens only after another full q.
        advance(Duration::from_millis(99)).await;
        yields(10).await;
        assert_eq!(snapshot(&runtime).committed_total, 0);
        advance(Duration::from_millis(1)).await;
        yields(20).await;
        assert_eq!(snapshot(&runtime).committed_total, 1);
        machine.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn t3_hard_deadline_beats_quiet_at_equal_instant() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, writes) = scripted_client(&ch);
        let (target, mut target_peer, _dropped) = mock_target(vec![]);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_millis(100),
        );
        let _flight = upload_and_write_flight(&ch, &mut target_peer).await;
        yields(10).await;
        advance(Duration::from_millis(100)).await;
        yields(20).await;
        machine.await.unwrap();
        let snap = snapshot(&runtime);
        assert_eq!(snap.committed_total, 0);
        assert_eq!(snap.cover_total.values().sum::<usize>(), 0);
        assert_eq!(snap.close_total.get(&("probe", "deadline")), Some(&1));
        assert!(writes.lock().unwrap().is_empty());
    }

    async fn prepare_branch(step: TryStep) -> (RealityV2MetricsSnapshot, Vec<u8>, Vec<u8>) {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, writes) = scripted_client(&ch);
        let (target, mut target_peer, _dropped) = mock_target(vec![step]);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        let flight = upload_and_write_flight(&ch, &mut target_peer).await;
        yields(10).await;
        advance(Duration::from_millis(100)).await;
        yields(30).await;
        let snap = snapshot(&runtime);
        let written = writes.lock().unwrap().clone();
        machine.abort();
        (snap, written, flight)
    }

    #[tokio::test(start_paused = true)]
    async fn t3_precommit_byte_appends_to_recovered_prefix_and_covers() {
        let (snap, written, flight) = prepare_branch(TryStep::Byte(0x99)).await;
        let mut expected = flight;
        expected.push(0x99);
        assert_eq!(
            snap.cover_total.get("late_dest_bytes"),
            Some(&1),
            "snap={snap:?}"
        );
        assert_eq!(snap.committed_total, 0);
        assert_eq!(
            written, expected,
            "cover download prefix is scanner prefix plus the exact tail byte"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn t3_precommit_eof_recovers_exact_prefix_for_half_close_cover() {
        let (snap, written, flight) = prepare_branch(TryStep::Eof).await;
        assert_eq!(snap.cover_total.get("dest_eof"), Some(&1), "snap={snap:?}");
        assert_eq!(snap.committed_total, 0);
        assert_eq!(
            written, flight,
            "EOF branch recovers the exact scanner prefix without a tail byte"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn t3_precommit_wouldblock_crosses_commit_barrier() {
        let (snap, written, flight) = prepare_branch(TryStep::WouldBlock).await;
        assert_eq!(snap.committed_total, 1);
        assert_eq!(snap.cover_total.values().sum::<usize>(), 0);
        assert!(!written.is_empty());
        assert_ne!(
            written, flight,
            "committed wire is resealed rather than the recovered target prefix"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn t3_emit_failure_after_partial_write_closes_without_cover_or_replay() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, writes) = scripted_client_failing_after_first_write(&ch, 64);
        let (target, mut target_peer, dropped) = mock_target(vec![]);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        let flight = upload_and_write_flight(&ch, &mut target_peer).await;
        yields(10).await;
        advance(Duration::from_millis(100)).await;
        yields(30).await;
        machine.await.unwrap();
        let snap = snapshot(&runtime);
        let written = writes.lock().unwrap().clone();
        assert_eq!(
            written.len(),
            64,
            "only the accepted partial emit reaches the client"
        );
        assert_ne!(
            written, flight,
            "post-commit failure must not replay the recovered target prefix"
        );
        assert_eq!(snap.committed_total, 1);
        assert_eq!(snap.close_total.get(&("emit", "emit_io")), Some(&1));
        assert_eq!(snap.cover_total.values().sum::<usize>(), 0);
        assert_eq!(snap.mimic_hit_total, 0);
        assert!(
            dropped.load(Ordering::Relaxed),
            "post-commit failure closes the target"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn t3_commit_is_counted_before_first_client_write_completes() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, writes) = scripted_client_with_capacity(&ch, 512);
        let (target, mut target_peer, _dropped) = mock_target(vec![]);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        let _flight = upload_and_write_flight(&ch, &mut target_peer).await;
        yields(10).await;
        advance(Duration::from_millis(100)).await;
        yields(20).await;
        assert!(
            !writes.lock().unwrap().is_empty(),
            "the small client buffer accepts only a partial first emit"
        );
        assert!(
            !machine.is_finished(),
            "emit remains incomplete while the peer does not drain the small buffer"
        );
        assert_eq!(
            snapshot(&runtime).committed_total,
            1,
            "the ownership barrier is counted before the first client write completes"
        );
        machine.abort();
    }

    async fn postcommit_event(eof: bool) -> RealityV2MetricsSnapshot {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, mut client_peer, _writes) = scripted_client(&ch);
        let (target, mut target_peer, _dropped) = mock_target(vec![]);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        let _flight = upload_and_write_flight(&ch, &mut target_peer).await;
        yields(10).await;
        advance(Duration::from_millis(100)).await;
        yields(20).await;
        assert_eq!(snapshot(&runtime).committed_total, 1);

        // Queue the target terminal event and an invalid client Finished
        // before the executor polls either branch again.  The biased monitor
        // must win even though the client future is also observably ready.
        if eof {
            drop(target_peer);
        } else {
            target_peer.write_all(&[0xaa]).await.unwrap();
        }
        client_peer
            .write_all(b"not-a-valid-finished")
            .await
            .unwrap();
        yields(30).await;
        machine.await.unwrap();
        snapshot(&runtime)
    }

    #[tokio::test(start_paused = true)]
    async fn t3_postcommit_target_tail_beats_simultaneous_client_result() {
        let snap = postcommit_event(false).await;
        assert_eq!(
            snap.close_total.get(&("wait_finished", "dest_tail")),
            Some(&1)
        );
        assert_eq!(snap.mimic_hit_total, 0);
        assert_eq!(snap.cover_total.values().sum::<usize>(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn t3_postcommit_target_eof_beats_simultaneous_client_result() {
        let snap = postcommit_event(true).await;
        assert_eq!(
            snap.close_total.get(&("wait_finished", "dest_eof")),
            Some(&1)
        );
        assert_eq!(snap.mimic_hit_total, 0);
        assert_eq!(snap.cover_total.values().sum::<usize>(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn t3_probe_cancellation_releases_hp_and_closes_target() {
        let runtime = runtime();
        let ch = capture_client_hello().await;
        let (client, _client_peer, _writes) = scripted_client(&ch);
        let (target, _target_peer, dropped) = mock_target(vec![]);
        let machine = spawn_machine(
            &runtime,
            client,
            target,
            Instant::now() + Duration::from_secs(5),
        );
        for _ in 0..100 {
            if snapshot(&runtime).probe_started_total == 1 {
                break;
            }
            yields(1).await;
        }
        assert_eq!(snapshot(&runtime).probe_started_total, 1);
        assert_eq!(snapshot(&runtime).active_probes, 1);
        machine.abort();
        let _ = machine.await;
        yields(5).await;
        let snap = snapshot(&runtime);
        assert_eq!(snap.active_probes, 0);
        assert_eq!(snap.active_handshakes, 0);
        assert!(
            dropped.load(Ordering::Relaxed),
            "cancellation drops the target socket"
        );
        assert_eq!(snap.close_total.get(&("probe", "canceled")), Some(&1));
    }
}
