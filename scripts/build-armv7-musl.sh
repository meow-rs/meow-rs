#!/usr/bin/env bash
# Build meow for armv7-unknown-linux-musleabihf (32-bit ARM, static musl).
#
# Why this target cannot use the cargo-zigbuild path the rest of the Linux
# matrix uses: zig's bundled musl headers declare time_t as 64-bit even on
# 32-bit targets (musl's Y2038 hardening), while Rust's libc crate types the
# same field as i32 there. bindgen therefore emits a 64-bit
# X509_VERIFY_PARAM_set_time and rustc rejects the mismatch inside `boring`
# (E0308, expected i64, found i32). Both toolchains are correct on their own;
# they simply disagree about a 32-bit time_t.
#
# The fix below is not a zig workaround but a different linker driver: a real
# musl cross toolchain (rustc + armv7-unknown-linux-musleabihf-gcc + sysroot),
# the same one the meowkrotik Docker image uses. musl-cross declares time_t as
# a plain 32-bit type, so bindgen and libc agree, and boring-sys needs nothing
# but a one-line cast (below) to make its own API call ABI-correct.
#
# Runs inside a container, with the repository bind-mounted at /src:
#
#   docker run --rm -v "$PWD:/src" -w /src \
#     messense/rust-musl-cross:armv7-musleabihf-amd64 \
#     bash scripts/build-armv7-musl.sh
#
# The image tag is suffixed with the HOST architecture (-amd64 / -arm64), not
# the target one. Result lands in target/armv7-unknown-linux-musleabihf/release/meow
# on the host, where the packaging steps of build.yml pick it up.

set -euo pipefail

TARGET=armv7-unknown-linux-musleabihf

# BoringSSL is built from C/C++ by boring-sys; its bindgen bindings need
# libclang, and CMake needs cmake. Neither is in the toolchain image.
apt-get update
apt-get install -y --no-install-recommends cmake clang libclang-dev
rm -rf /var/lib/apt/lists/*

# Build with the pinned channel from rust-toolchain.toml, not with whatever
# rustc the image happens to ship. RUSTUP_TOOLCHAIN overrides the file's
# component list too (rustfmt/clippy are not needed to build a release).
tc=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n1)
if [ -z "$tc" ]; then
    echo "could not parse channel from rust-toolchain.toml" >&2
    exit 1
fi
rustup toolchain install "$tc" --profile minimal
# The image's own rustc ships cross-built std for this target, but the pinned
# channel just installed does not: without this, `can't find crate for core`.
# (Same rule as build.yml's own setup step: targets go on the pinned channel.)
rustup target add --toolchain "$tc" "$TARGET"
export RUSTUP_TOOLCHAIN="$tc"

# bindgen (meow-lwip and boring-sys) resolves headers relative to the BUILD
# MACHINE unless it is told otherwise: without the sysroot below, the clang
# invocation parses the host's /usr/include and meow-lwip dies on
# 'bits/wordsize.h file not found'. TARGET_HOME and TARGET_C_INCLUDE_PATH are
# exported by the toolchain image.
export BINDGEN_EXTRA_CLANG_ARGS="--target=${TARGET} --sysroot=${TARGET_HOME} -I${TARGET_C_INCLUDE_PATH}"

# +crt-static is what the toolchain image already sets; repeating it here is
# deliberate (an env var inherited from the base image cannot be expanded by a
# Dockerfile, and this script may be reused outside one).
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
patched=0
for f in "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/boring-*/src/x509/verify.rs; do
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

cargo build --release --locked --target "$TARGET" --bin meow

# Cheap guard against a regression that would ship a binary needing GLIBC_2.28:
# that is the exact failure this target exists to avoid.
file "target/${TARGET}/release/meow"