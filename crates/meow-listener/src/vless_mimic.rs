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
pub(crate) struct DialedTarget {
    pub(crate) stream: TcpStream,
    pub(crate) connect_elapsed: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DialFirstDialError {
    Resolve,
    Connect,
}

struct CoverHandoff {
    client: Box<dyn Stream>,
    target: TcpStream,
    upload_prefix: Vec<u8>,
    download_prefix: Vec<u8>,
    uploaded: u64,
    target_eof: bool,
    reason: CoverReason,
}

async fn handoff_cover(
    reality: &RealityRuntime,
    handoff: CoverHandoff,
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
    target: &mut TcpStream,
    bytes: &[u8],
    probe_deadline: Instant,
    handshake_deadline: Instant,
) -> UploadWriteOutcome {
    let mut write = Box::pin(target.write(bytes));
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(handshake_deadline) => UploadWriteOutcome::HandshakeDeadline,
        _ = tokio::time::sleep_until(probe_deadline) => UploadWriteOutcome::ProbeDeadline,
        result = &mut write => {
            match result {
                Ok(n) if n == bytes.len() => UploadWriteOutcome::Written,
                Ok(_) | Err(_) => UploadWriteOutcome::Io,
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
    target: &mut TcpStream,
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
                        match scanner.push(&scratch[..n]) {
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

async fn drive_post_commit(
    mut target: TcpStream,
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
pub(crate) async fn run_dial_first<D>(
    reality: &RealityRuntime,
    client: TcpStream,
    handshake_deadline: Instant,
    handshake_permit: Option<OwnedSemaphorePermit>,
    dial: D,
) -> Option<Box<dyn Stream>>
where
    D: Future<Output = Result<DialedTarget, DialFirstDialError>>,
{
    let metrics = Arc::clone(&reality.metrics);
    let mut accountant = CloseAccountant::new(metrics);
    let dial_begin = Instant::now();
    let dial_deadline = handshake_deadline.min(dial_begin + Duration::from_secs(3));

    let mut preflight = Box::pin(
        reality
            .server
            .verify_client_hello(Box::new(client) as Box<dyn Stream>),
    );
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
