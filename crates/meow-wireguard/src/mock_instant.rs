// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! In-crate replacement for upstream's `mock_instant` dev-dependency (not
//! vendored). Used only when the `mock-instant` feature is enabled — it
//! provides the same surface the gated code touches (`Instant::now`,
//! `Instant::duration_since`, `Instant::elapsed`, `MockClock::advance`) with
//! matching semantics: a process-global offset applied over
//! `std::time::Instant`, so `MockClock::advance` moves every `Instant::now()`
//! taken afterwards.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Global offset added to the real clock, in nanoseconds.
static OFFSET_NANOS: AtomicU64 = AtomicU64::new(0);

fn offset() -> Duration {
    Duration::from_nanos(OFFSET_NANOS.load(Ordering::SeqCst))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant {
    t: std::time::Instant,
}

impl Instant {
    pub(crate) fn now() -> Self {
        Self {
            t: std::time::Instant::now() + offset(),
        }
    }

    pub(crate) fn duration_since(&self, earlier: Instant) -> Duration {
        self.t
            .checked_duration_since(earlier.t)
            .unwrap_or(Duration::ZERO)
    }

    pub(crate) fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }
}

/// Advances the global mock clock. Only referenced by `#[cfg(test)]` code, so
/// it does not exist in non-test builds even when the feature is on.
#[cfg(test)]
pub(crate) struct MockClock;

#[cfg(test)]
impl MockClock {
    pub(crate) fn advance(time: Duration) {
        OFFSET_NANOS.fetch_add(time.as_nanos() as u64, Ordering::SeqCst);
    }
}
