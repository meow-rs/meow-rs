#!/usr/bin/env bash
# End-to-end transparent proxy integration test using Docker.
#
# Builds a Linux meow binary in a builder container with the cargo target
# cache on a host-mounted directory, then runs the netns/nftables assertions
# in a small privileged runtime image. Keeping cargo's multi-GB target out of
# image layers matters on Docker Desktop VMs with small disks; CI uses a
# temporary cache and recreates it on every run.
#
# Usage: bash tests/test_tproxy_docker.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Dependency check ---
if ! command -v docker &>/dev/null; then
    echo "SKIP: docker not found in PATH"
    [ "${MEOW_REQUIRE_DOCKER:-0}" != 1 ] || exit 1
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker daemon not running"
    [ "${MEOW_REQUIRE_DOCKER:-0}" != 1 ] || exit 1
    exit 0
fi

BUILDER_IMAGE="${MEOW_TPROXY_BUILDER_IMAGE:-meow-tproxy-builder}"
FEATURES="ss,trojan,vless,vless-vision,vless-encryption,vmess,snell,hysteria2,anytls,ech-tls-tunnel,dns-server,dns-encrypted,listener-http,listener-socks5,listener-tproxy,listener-mixed"

if [ -n "${MEOW_TPROXY_CACHE_ROOT:-}" ]; then
    CACHE_ROOT="$MEOW_TPROXY_CACHE_ROOT"
    CACHE_TEMP=0
elif [ -d /Volumes/CK_Data ]; then
    CACHE_ROOT="/Volumes/CK_Data/meow-tproxy-docker-cache"
    CACHE_TEMP=0
else
    CACHE_ROOT="$(mktemp -d /tmp/meow-tproxy-build.XXXXXX)"
    CACHE_TEMP=1
fi
CHECKOUT_ID="$(printf %s "$ROOT_DIR" | cksum | awk '{print $1}')"
RUN_ID="$$-$(date +%s)-$RANDOM"
DOCKER_IMAGE="meow-tproxy-test-$RUN_ID"
TARGET_DIR="$CACHE_ROOT/target-$CHECKOUT_ID"
CARGO_HOME_DIR="$CACHE_ROOT/cargo-home"
BUILD_CTX="$CACHE_ROOT/context-$RUN_ID"
EMPTY_CTX="$CACHE_ROOT/empty-context-$RUN_ID"
CONTAINER_LOG=""
mkdir -p "$TARGET_DIR" "$CARGO_HOME_DIR" "$BUILD_CTX" "$EMPTY_CTX"

cleanup() {
    docker image rm -f "$DOCKER_IMAGE" >/dev/null 2>&1 || true
    [ -z "$CONTAINER_LOG" ] || rm -f "$CONTAINER_LOG"
    rm -rf "$BUILD_CTX" "$EMPTY_CTX" 2>/dev/null || true
    if [ "$CACHE_TEMP" -eq 1 ]; then
        rm -rf "$CACHE_ROOT" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== Preparing builder image ==="
if [ "$BUILDER_IMAGE" = "meow-tproxy-builder" ] \
    && ! docker image inspect "$BUILDER_IMAGE" >/dev/null 2>&1; then
    docker build -t "$BUILDER_IMAGE" -f - "$EMPTY_CTX" <<'DOCKERFILE'
FROM rust:1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev cmake git pkg-config
DOCKERFILE
fi

echo "=== Building Linux test binaries (cache: $CACHE_ROOT) ==="
RUSTC_VERSION="$(docker run --rm "$BUILDER_IMAGE" rustc --version | awk '{print $2}')"
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$ROOT_DIR:/src:ro" \
    -v "$TARGET_DIR:/target" \
    -v "$CARGO_HOME_DIR:/cargo-home" \
    -e CARGO_HOME=/cargo-home \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_PROFILE_DEV_DEBUG=0 \
    -e RUSTUP_TOOLCHAIN="$RUSTC_VERSION" \
    -e MEOW_FEATURES="$FEATURES" \
    "$BUILDER_IMAGE" \
    sh -c '
        set -eu
        cd /src
        # TProxy does not need TUN/lwIP; retain the transport coverage without it.
        cargo build --locked -p meow-app --no-default-features \
            --features="$MEOW_FEATURES"
        strip -o /target/meow-tproxy /target/debug/meow
        rustc --edition=2021 -O -C debuginfo=0 \
            -o /target/tproxy-e2e-helper \
            /src/tests/tproxy-docker/udp-e2e-helper.rs
        strip /target/tproxy-e2e-helper
    '

rm -rf "$BUILD_CTX"
mkdir -p "$BUILD_CTX"
cp "$TARGET_DIR/meow-tproxy" "$BUILD_CTX/meow"
cp "$TARGET_DIR/tproxy-e2e-helper" "$BUILD_CTX/tproxy-e2e-helper"
cp \
    "$ROOT_DIR/tests/tproxy-docker/meow-tproxy.yaml" \
    "$ROOT_DIR/tests/tproxy-docker/meow-tproxy-ext.yaml" \
    "$ROOT_DIR/tests/tproxy-docker/meow-tproxy-udp.yaml" \
    "$ROOT_DIR/tests/tproxy-docker/meow-tproxy-udp6-only.yaml" \
    "$ROOT_DIR/tests/tproxy-docker/meow-tproxy-multi.yaml" \
    "$ROOT_DIR/tests/tproxy-docker/guest-init.sh" \
    "$BUILD_CTX/"

echo "=== Building test container ==="
docker build -t "$DOCKER_IMAGE" -f - "$BUILD_CTX" <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables iproute2 netcat-traditional bash ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY meow /usr/local/bin/meow
COPY tproxy-e2e-helper /usr/local/bin/tproxy-e2e-helper
COPY meow-tproxy.yaml /etc/meow-tproxy.yaml
COPY meow-tproxy-ext.yaml /etc/meow-tproxy-ext.yaml
COPY meow-tproxy-udp.yaml /etc/meow-tproxy-udp.yaml
COPY meow-tproxy-udp6-only.yaml /etc/meow-tproxy-udp6-only.yaml
COPY meow-tproxy-multi.yaml /etc/meow-tproxy-multi.yaml
COPY guest-init.sh /run-tests.sh
RUN chmod +x /run-tests.sh /usr/local/bin/meow /usr/local/bin/tproxy-e2e-helper
DOCKERFILE

echo ""
echo "=== Running tproxy tests in container ==="

CONTAINER_LOG=$(mktemp)
RUN_STATUS=0
docker run --rm --privileged \
    "$DOCKER_IMAGE" \
    /bin/bash /run-tests.sh 2>&1 | tee "$CONTAINER_LOG" || RUN_STATUS=$?

echo ""
echo "=== Parsing test results ==="

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

while IFS= read -r line; do
    test_name="${line#TEST_PASS:}"
    echo "  PASS: $test_name"
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
done < <(grep "^TEST_PASS:" "$CONTAINER_LOG" 2>/dev/null || true)

while IFS= read -r line; do
    test_name="${line#TEST_FAIL:}"
    echo "  FAIL: $test_name"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
done < <(grep "^TEST_FAIL:" "$CONTAINER_LOG" 2>/dev/null || true)

# IPv6 is not optional in this job: an interrupted guest, a kernel without
# IPv6/TPROXY support, or a renamed/missing assertion must not produce green.
REQUIRED_V6_TESTS="
udp6_kernel_support
udp6_nft_installed
udp_dual_listener_sockets
udp4_two_packet_exact_source
udp4_log_not_mapped
udp6_two_packet_exact_source
udp6_flow_logged
udp6_only_bind
udp6_only_relay
udp6_fake_aaaa
udp6_fake_unmapped_drop
udp6_no_rule_no_reply
udp6_rules_persist
"
MISSING_REQUIRED=0
for test_name in $REQUIRED_V6_TESTS; do
    if ! grep -qx "TEST_PASS:$test_name" "$CONTAINER_LOG"; then
        echo "  MISSING/FAILED required IPv6 assertion: $test_name"
        MISSING_REQUIRED=1
    fi
done

echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $TOTAL_COUNT total"

if [ "$RUN_STATUS" -ne 0 ] || ! grep -qx ALL_TESTS_DONE "$CONTAINER_LOG"; then
    echo "FAIL: container did not complete (exit $RUN_STATUS)"
    exit 1
elif [ "$TOTAL_COUNT" -eq 0 ]; then
    echo ""
    echo "=== FAIL: No tests ran ==="
    exit 1
elif [ "$FAIL_COUNT" -gt 0 ] || [ "$MISSING_REQUIRED" -ne 0 ]; then
    echo ""
    echo "=== FAIL: $FAIL_COUNT test(s) failed ==="
    exit 1
else
    echo ""
    echo "=== All TProxy integration tests passed ==="
    exit 0
fi
