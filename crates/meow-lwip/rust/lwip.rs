#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]
#![allow(clippy::all)]
// Newer glibc (2.43 on Ubuntu 26.04, not 2.39 on 24.04) declares
// `_IO_FILE::_flags2` as a 24-bit bitfield, and bindgen's accessors for a
// signed bitfield transmute between `c_int` and `u32`.
#![allow(
    unnecessary_transmutes,
    reason = "bindgen's signed-bitfield accessors; generated code"
)]
// Rust 1.99 checks extern declarations of the allocator symbols std uses:
// bindgen declares libc's `malloc`/`realloc` with `c_ulong` sizes, which
// are `usize`-sized on the Unix targets lwIP builds for. `unknown_lints`
// keeps the pinned toolchain, which predates the lint, quiet.
#![allow(unknown_lints, reason = "the lint below is new in Rust 1.99")]
#![allow(
    suspicious_runtime_symbol_definitions,
    reason = "bindgen's libc malloc/realloc declarations; generated code"
)]

// Note the bindings are generated on macOS.
// This shouldn't be problematic since we only use lwip functions from
// the bindings. We should have the bindings automatically generated
// for each target at compile time, but I couldn't find a way to make
// bindgen work with cross.
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
