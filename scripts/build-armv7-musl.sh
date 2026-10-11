#!/usr/bin/env bash
# Build meow for armv7-unknown-linux-musleabihf (32-bit ARM, static musl).
#
# Why this target cannot use the cargo-zigbuild path the rest of the Linux
# matrix uses. The blocker is not the 32-bit width itself: musl 1.2.x headers
# (both zig's bundled copy and this toolchain's) declare time_t as 64-bit on
# 32-bit targets (time64/Y2038 hardening), while Rust's libc crate types the
# same field as i32 there. bindgen therefore emits a 64-bit
# X509_VERIFY_PARAM_set_time and rustc rejects the mismatch inside `boring`
# (E0308, expected i64, found i32). With zig, getting past that means patching
# zig's bundled headers; zig-linked static armv7 binaries were also
# unreliable under QEMU in our testing.
#
# This script takes a different linker driver instead: a real musl cross
# toolchain (rustc + armv7-unknown-linux-musleabihf-gcc + genuine target
# sysroot). The time64-vs-libc disagreement exists here too; it is bridged by
# the one-line cast below, which makes `boring`'s single set_time call
# ABI-correct (meow-rs never calls set_time, so nothing on a live path
# changes).
#
# Runs inside a container, with the repository bind-mounted at /src:
#
#   docker run --rm -v "$PWD:/src" -w /src \
#     ghcr.io/rust-cross/rust-musl-cross:armv7-musleabihf-amd64 \
#     bash scripts/build-armv7-musl.sh
#
# The image tag is suffixed with the HOST architecture (-amd64 / -arm64), not
# the target one. Result lands in target/armv7-unknown-linux-musleabihf/release/meow
# on the host, where the packaging steps of build.yml pick it up.

set -euo pipefail

TARGET=armv7-unknown-linux-musleabihf

# BoringSSL is built from C/C++ by boring-sys; its bindgen bindings need
# libclang, and CMake needs cmake. `file` backs the static-linkage assert at
# the end. None are in the toolchain image.
apt-get update
apt-get install -y --no-install-recommends cmake clang libclang-dev file
rm -rf /var/lib/apt/lists/*

# Build with the pinned channel from rust-toolchain.toml, not with whatever
# rustc the image happens to ship. RUSTUP_TOOLCHAIN overrides the file's
# component list too (rustfmt/clippy are not needed to build a release).
tc=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n1)
if [ -z "$tc" ]; then
    echo "could not parse channel from rust-toolchain.toml" >&2
    exit 1
fi
# The download is retried: static.rust-lang.org occasionally stalls mid-body
# and rustup then aborts the whole leg on a single truncated read (seen
# locally: 16 KB of 898 KB, then a timeout). Five attempts with a short
# pause between them turn a flake into a slower build, not a red build.
installed=0
for attempt in 1 2 3 4 5; do
    if rustup toolchain install "$tc" --profile minimal --no-self-update; then
        installed=1
        break
    fi
    echo "::warning::rustup toolchain install $tc failed (attempt $attempt/5) — retrying"
    sleep 10
done
if [ "$installed" -eq 0 ]; then
    echo "could not install the pinned toolchain $tc" >&2
    exit 1
fi
# The image's own rustc ships cross-built std for this target, but the pinned
# channel just installed does not: without this, `can't find crate for core`.
# (Same rule as build.yml's own setup step: targets go on the pinned channel.)
# The target's rust-std is a second download from the same flaky host, so it
# gets the same retry treatment: a truncated read here fails the leg with the
# same "can't find crate for core" as no target at all.
target_added=0
for attempt in 1 2 3 4 5; do
    if rustup target add --toolchain "$tc" "$TARGET"; then
        target_added=1
        break
    fi
    echo "::warning::rustup target add $tc $TARGET failed (attempt $attempt/5) — retrying"
    sleep 10
done
if [ "$target_added" -eq 0 ]; then
    echo "could not add target $TARGET to the pinned toolchain $tc" >&2
    exit 1
fi
export RUSTUP_TOOLCHAIN="$tc"

# bindgen (meow-lwip and boring-sys) resolves headers relative to the BUILD
# MACHINE unless it is told otherwise: without the sysroot below, the clang
# invocation parses the host's /usr/include and meow-lwip dies on
# 'bits/wordsize.h file not found'. TARGET_HOME and TARGET_C_INCLUDE_PATH are
# exported by the toolchain image.
export BINDGEN_EXTRA_CLANG_ARGS="--target=${TARGET} --sysroot=${TARGET_HOME} -I${TARGET_C_INCLUDE_PATH}"

# This assignment REPLACES the toolchain image's RUSTFLAGS, not extends it —
# that is deliberate: the image default already carries +crt-static, and the
# link flags below are only meaningful together with it. Stated explicitly so
# nobody "simplifies" the image var back in and drops the -lgcc bridge.
#
# -lgcc: a static musl link runs with -nodefaultlibs, so libgcc is not linked,
# and the __sync_* builtins that libstdc++.a needs (BoringSSL and quiche are
# C++) are then undefined. --allow-multiple-definition silences libgcc's own
# definitions of those symbols clashing with Rust's compiler_builtins.
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-lgcc -C link-arg=-lgcc_eh -C link-arg=-Wl,--allow-multiple-definition"

# A slow link drops crate downloads long before the real timeout, so cargo
# needs to be told that a slow response is not a dead one.
export CARGO_HTTP_LOW_SPEED_LIMIT=0
export CARGO_HTTP_TIMEOUT=600
export CARGO_NET_RETRY=10

cargo fetch --locked

# boring types X509VerifyParam::set_time's argument as Rust libc's time_t
# (i32 on 32-bit targets) while this musl declares time_t 64-bit, so bindgen
# generates a 64-bit signature and rustc fails on the mismatch. The cast makes
# the call ABI-correct; meow-rs never calls set_time, so nothing else changes.
#
# Every extracted version is patched, not just the first match: with a warm
# cargo registry a previous build of another meow-rs tag can leave more than
# one boring-<version> behind, and sed is idempotent here because the already
# patched line no longer matches the pattern.
#
# The locked version is checked separately, because "some boring copy in the
# registry got patched" is not the same as "the boring this build compiles
# got patched": if a boring release moves that call, the sed below matches
# nothing, and the build would die on the type mismatch with a message that
# says nothing about the patch. This check turns that into one clear line.
locked_boring=$(awk '/^\[\[package\]\]/{pkg=""} /^name = "boring"$/{pkg="boring"} pkg=="boring" && /^version = /{gsub(/"/,"",$3); print $3; exit}' Cargo.lock)
if [ -z "$locked_boring" ]; then
    echo "could not parse the boring version from Cargo.lock" >&2
    exit 1
fi
patched=0
for f in "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/boring-[0-9]*/src/x509/verify.rs; do
    [ -f "$f" ] || continue
    sed -i 's|X509_VERIFY_PARAM_set_time(self\.as_ptr(), time)|X509_VERIFY_PARAM_set_time(self.as_ptr(), time.into())|' "$f"
    if grep -q 'X509_VERIFY_PARAM_set_time(self.as_ptr(), time.into())' "$f"; then
        patched=$((patched + 1))
    fi
done
if [ "$patched" -eq 0 ]; then
    echo "no vendored boring sources found in the cargo registry" >&2
    exit 1
fi
locked_patched=0
for f in "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/boring-"$locked_boring"/src/x509/verify.rs; do
    [ -f "$f" ] || continue
    if grep -q 'X509_VERIFY_PARAM_set_time(self.as_ptr(), time.into())' "$f"; then
        locked_patched=1
    fi
done
if [ "$locked_patched" -eq 0 ]; then
    echo "boring $locked_boring does not contain the call this script patches;" >&2
    echo "update the sed pattern (and docs/RELEASING.md) for the new layout" >&2
    exit 1
fi

cargo build --release --locked --target "$TARGET" --bin meow

# Hard guard against a regression that would ship a binary needing GLIBC_2.28:
# that is the exact failure this target exists to avoid. Fails the build if
# the linker ever produces a dynamically linked binary.
file "target/${TARGET}/release/meow" | grep -q 'statically linked'