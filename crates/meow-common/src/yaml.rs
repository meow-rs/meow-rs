//! Shared bounds for YAML document ingest — the one place every YAML
//! front-end takes them from.
//!
//! The workspace's YAML backend (serde-saphyr) deserializes by recursive
//! descent: each document nesting level costs stack, measured at ≈26 KiB
//! per level in a debug build (≈6-8 KiB in release). The in-parser depth
//! budget [`MAX_DEPTH`] exists to trip long before that recursion can
//! overflow — but it can only do so while the parser's frames still fit on
//! the *caller's* stack. The shipped `meow`/`meow-cli` binaries parse on a
//! 1 MiB main thread that is already ~350-400 KiB deep in async-poll
//! frames, where the fatal depth measures ≈25 — *below* the 32-level
//! budget, so a deep document turned "config too deep" into a raw
//! `thread 'main' has overflowed its stack` abort instead of an error
//! (serde-saphyr migration review, F1).
//!
//! [`run_on_parse_stack`] closes that structurally: the descend runs on a
//! dedicated thread carrying [`PARSE_STACK_SIZE`] bytes of stack — large
//! enough that [`MAX_DEPTH`] always trips first, on any caller, on any
//! build profile. Every document ingest point parses through it:
//! meow-config's `parse_raw_yaml`/`parse_yaml_value` (config file,
//! `--config-string`, `PUT /configs`, subscription / proxy-provider /
//! rule-set payloads) and meow-cli's local config read. meow-cli links
//! only meow-common among the engine crates — the reason these knobs live
//! here rather than in meow-config.

/// Nesting-depth budget enforced inside the YAML parser at every ingest
/// point (the backend's `budget.max_depth` option).
///
/// 32 sits far above any real config (~12 levels is a deep one) yet far
/// below what a [`PARSE_STACK_SIZE`] stack can descend (~300 levels in a
/// debug build), so the budget always beats the overflow by a wide margin.
/// Both YAML front-ends — meow-config's `yaml_options()` and meow-cli's
/// `parse_config` — must use this exact value: it is the user-facing depth
/// contract, and a drift between front-ends would let one binary reject a
/// document the other accepts.
pub const MAX_DEPTH: usize = 32;

/// Stack size for the dedicated parse thread [`run_on_parse_stack`]
/// spawns.
///
/// The binding constraint: [`MAX_DEPTH`] must trip before the stack is
/// exhausted. Reaching the depth-33 trip point costs ≈0.9 MiB of descend
/// in a debug build (33 × ~26 KiB) and ~0.25 MiB in release, so 8 MiB
/// carries ~9× / ~32× headroom respectively — margin for codegen
/// differences across toolchains and targets. 8 MiB is also the stack
/// `cargo test` gives each worker thread by default, so the parse runs
/// under the same budget the test suite exercises it with. The
/// reservation is virtual — pages commit only on use and are released
/// when the short-lived parse thread exits — so the size costs a slice
/// of address space, not resident memory; on the 32-bit release targets
/// (`build.yml`'s armv7/i686, 2 GiB address space) halving it from
/// 16 MiB halves that reservation too.
pub const PARSE_STACK_SIZE: usize = 8 << 20;

/// Parse `doc` on a dedicated thread carrying [`PARSE_STACK_SIZE`] bytes
/// of stack, returning `parse`'s result.
///
/// Every YAML ingest point wraps its backend call in this: the recursive
/// descend gets a stack the [`MAX_DEPTH`] budget always trips inside
/// instead of inheriting whatever the caller has left — the shipped
/// binaries' 1 MiB main thread had ~600 KiB, which is what let deep
/// documents abort the process before the budget could fire. The join
/// blocks the caller synchronously: call sites are startup, hot-reload
/// and provider-refresh paths that already parsed inline, so the caller
/// sees the same latency plus one thread spawn.
///
/// `doc` is passed separately and re-borrowed inside the scoped spawn so
/// callers keep `&str` documents — no copy — while `parse` (non-capturing
/// at every call site) stays `'static`. The caller's tracing dispatcher
/// is carried onto the parse thread so log/warn lines emitted inside
/// `parse` reach the subscriber in effect at the call site.
///
/// A panic inside `parse` is re-thrown to the caller. An `Err` return
/// means the parse thread could not be spawned (OS thread exhaustion) —
/// never a stack overflow: an overflow aborts the process in a way no API
/// can catch, which is exactly what [`PARSE_STACK_SIZE`] exists to rule
/// out.
pub fn run_on_parse_stack<F, T>(doc: &str, parse: F) -> std::io::Result<T>
where
    F: FnOnce(&str) -> T + Send + 'static,
    T: Send + 'static,
{
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("yaml-parse".into())
            .stack_size(PARSE_STACK_SIZE)
            .spawn_scoped(scope, move || {
                tracing::dispatcher::with_default(&dispatch, || parse(doc))
            })
            .map(|handle| match handle.join() {
                Ok(value) => value,
                Err(payload) => std::panic::resume_unwind(payload),
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_the_parse_and_returns_its_value() {
        let result = run_on_parse_stack("k: v", str::len).unwrap();
        assert_eq!(result, 4);
    }

    /// A panic inside the parse must reach the caller, not die silently on
    /// the parse thread.
    #[test]
    #[should_panic(expected = "parse exploded")]
    fn propagates_a_parse_panic() {
        let _: std::io::Result<()> =
            run_on_parse_stack("x", |_| -> () { panic!("parse exploded") });
    }
}
