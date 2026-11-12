// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// PATCH(deps): upstream called nix::time::clock_gettime; `nix` is removed with
// the device module, so the same call is made through `libc` directly.
// Semantics are unchanged: CLOCK_BOOTTIME on Linux-family targets (counts
// time spent suspended), CLOCK_MONOTONIC on Apple/FreeBSD.
#![allow(unsafe_code)]

use std::time::Duration;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd"
))]
const CLOCK_ID: libc::clockid_t = libc::CLOCK_MONOTONIC;
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd"
)))]
const CLOCK_ID: libc::clockid_t = libc::CLOCK_BOOTTIME;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant {
    t: libc::timespec,
}

impl Instant {
    pub(crate) fn now() -> Self {
        // SAFETY: `t` is a valid out-pointer for clock_gettime to write into,
        // and the return code is checked. std::time::Instant unwraps clock
        // failures as well, so feel safe doing so here.
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(unsafe { libc::clock_gettime(CLOCK_ID, &mut t) }, 0);
        Self { t }
    }

    fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        const NANOSECOND: libc::c_long = 1_000_000_000;
        let (tv_sec, tv_nsec) = if self.t.tv_nsec < earlier.t.tv_nsec {
            (
                self.t.tv_sec - earlier.t.tv_sec - 1,
                self.t.tv_nsec - earlier.t.tv_nsec + NANOSECOND,
            )
        } else {
            (
                self.t.tv_sec - earlier.t.tv_sec,
                self.t.tv_nsec - earlier.t.tv_nsec,
            )
        };

        if tv_sec < 0 {
            None
        } else {
            Some(Duration::new(tv_sec as _, tv_nsec as _))
        }
    }

    pub(crate) fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(Duration::ZERO)
    }
}
