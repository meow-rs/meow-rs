#!/usr/bin/env bash
# End-to-end transparent proxy integration test using Docker.
#
# Runs a privileged Linux container with nftables support, builds meow
# inside it, starts the tproxy listener, and verifies firewall setup,
# traffic interception, SNI extraction, and clean teardown.
#
# Works on both macOS (Docker Desktop uses native ARM64 VM) and Linux.
#
# Requirements: docker
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

echo "=== Building test container ==="

# Build a Docker image with Rust toolchain + nftables
DOCKER_IMAGE="meow-tproxy-test"

docker build -t "$DOCKER_IMAGE" -f - "$ROOT_DIR" <<'DOCKERFILE'
FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev cmake git pkg-config
WORKDIR /src
COPY . .
# BoringSSL is mandatory, including for minimal TLS builds. Use a glibc
# builder so bindgen can load libclang, and install its CMake/git toolchain.
# TProxy does not need TUN/lwIP; retain the transport coverage without it.
# debuginfo=0 + same-layer cleanup keep the build inside small Docker VM
# disks — a default debug build of this dep tree is several GB.
RUN CARGO_PROFILE_DEV_DEBUG=0 cargo build -p meow-app --no-default-features \
    --features=ss,trojan,vless,vless-vision,vless-encryption,vmess,snell,hysteria2,anytls,ech-tls-tunnel,dns-server,dns-encrypted,listener-http,listener-socks5,listener-tproxy,listener-mixed \
    2>&1 \
    && rm -rf /src/target/debug/incremental /src/target/debug/.fingerprint \
        /src/target/debug/deps /src/target/debug/build

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables iproute2 netcat-traditional bash ca-certificates libstdc++6
COPY --from=builder /src/target/debug/meow /usr/local/bin/meow
COPY tests/tproxy-docker/meow-tproxy.yaml /etc/meow-tproxy.yaml
COPY tests/tproxy-docker/meow-tproxy-ext.yaml /etc/meow-tproxy-ext.yaml
COPY tests/tproxy-docker/meow-tproxy-udp.yaml /etc/meow-tproxy-udp.yaml
COPY tests/tproxy-docker/meow-tproxy-multi.yaml /etc/meow-tproxy-multi.yaml
COPY tests/tproxy-docker/guest-init.sh /run-tests.sh
RUN chmod +x /run-tests.sh
DOCKERFILE

echo ""
echo "=== Running tproxy tests in container ==="

CONTAINER_LOG=$(mktemp)
trap 'rm -f "$CONTAINER_LOG"' EXIT
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


echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $TOTAL_COUNT total"

if [ "$RUN_STATUS" -ne 0 ] || ! grep -qx ALL_TESTS_DONE "$CONTAINER_LOG"; then
    echo "FAIL: container did not complete (exit $RUN_STATUS)"
    exit 1
elif [ "$TOTAL_COUNT" -eq 0 ]; then
    echo ""
    echo "=== FAIL: No tests ran ==="
    exit 1
elif [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "=== FAIL: $FAIL_COUNT test(s) failed ==="
    exit 1
else
    echo ""
    echo "=== All TProxy integration tests passed ==="
    exit 0
fi
