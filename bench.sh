#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GO_BINARY="${GO_BINARY:-}"
DURATION="${DURATION:-10}"

# The steady leg samples the middle third of the window — catch a too-
# short duration now instead of after the ~10 min main run.
if [ "$DURATION" -lt 3 ]; then
    echo "DURATION=$DURATION too short — the steady leg needs >= 3 s" >&2
    exit 1
fi

echo "=== Building meow-rs (release) ==="
cargo build --release -p meow-app -p meow-bench

RUST_BINARY="./target/release/meow"
BENCH_BINARY="./target/release/meow-bench"

# Download Go mihomo if not provided
if [ -z "$GO_BINARY" ]; then
    ARCH=$(uname -m)
    case "$ARCH" in
        arm64|aarch64) GO_ARCH="arm64" ;;
        x86_64)        GO_ARCH="amd64" ;;
        *)             echo "Unsupported arch: $ARCH"; exit 1 ;;
    esac

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    GO_BINARY="./target/bench/mihomo-go"

    # Resolve the latest release tag first: the cached binary must match
    # it — `target/` is persisted by the CI cache, so without the drift
    # check the Go comparator silently freezes at whatever release was
    # latest when the cache was first written.
    gh_missing() {
        echo "gh CLI unavailable — cannot resolve the latest mihomo release."
        echo "Install/authenticate gh, or run: GO_BINARY=/path/to/mihomo-go bash bench.sh"
    }
    if ! command -v gh >/dev/null 2>&1; then
        if [ -f "$GO_BINARY" ]; then
            echo "Using cached Go binary: $GO_BINARY (gh unavailable — version unchecked)"
        else
            gh_missing
            exit 1
        fi
    else
        LATEST=$(gh release view --repo MetaCubeX/mihomo --json tagName -q .tagName) || {
            gh_missing
            exit 1
        }
        STAMP=""
        [ -f target/bench/mihomo-version ] && STAMP=$(cat target/bench/mihomo-version)

        if [ ! -f "$GO_BINARY" ] || [ "$STAMP" != "$LATEST" ]; then
            echo ""
            echo "=== Downloading Go mihomo ==="
            mkdir -p target/bench
            echo "Latest Go mihomo release: $LATEST (cached: ${STAMP:-none})"

            PATTERN="mihomo-${OS}-${GO_ARCH}-${LATEST}.gz"
            echo "Downloading: $PATTERN"

            gh release download "$LATEST" --repo MetaCubeX/mihomo \
                --pattern "$PATTERN" --dir target/bench || {
                echo "Download failed. You can manually download from:"
                echo "  https://github.com/MetaCubeX/mihomo/releases"
                echo "Then run: GO_BINARY=/path/to/mihomo-go bash bench.sh"
                exit 1
            }

            gunzip -f "target/bench/$PATTERN"
            mv "target/bench/mihomo-${OS}-${GO_ARCH}-${LATEST}" "$GO_BINARY"
            chmod +x "$GO_BINARY"
            echo "$LATEST" > target/bench/mihomo-version
            echo "Go binary: $GO_BINARY"
        else
            echo "Using cached Go binary: $GO_BINARY ($STAMP)"
        fi
    fi

    # Provenance for results.json: meow-bench records $MIHOMO_VERSION.
    # The stamp file only describes the managed binary — a caller-provided
    # GO_BINARY must not inherit it (it may be a different release).
    if [ -z "${MIHOMO_VERSION:-}" ] && [ -f target/bench/mihomo-version ]; then
        MIHOMO_VERSION=$(cat target/bench/mihomo-version)
    fi
fi
export MIHOMO_VERSION="${MIHOMO_VERSION:-}"

# Proxied-outbound workload (#558): needs a sing-box binary as the VLESS
# server half.  Auto-detect on PATH when unset; SINGBOX_BIN (the smux
# suite's spelling) is accepted as an alias.  Skip the leg (loudly) when
# no server binary exists.
SINGBOX_BINARY="${SINGBOX_BINARY:-${SINGBOX_BIN:-$(command -v sing-box || true)}}"
PROXIED_ARGS=()
if [ -n "$SINGBOX_BINARY" ]; then
    PROXIED_ARGS+=(--proxy-config config-bench-vless.yaml --singbox-binary "$SINGBOX_BINARY")
    echo "sing-box: $SINGBOX_BINARY — proxied workload enabled"
else
    echo "sing-box not found — proxied workload skipped (set SINGBOX_BINARY to enable)"
fi

echo ""
echo "=== Binary sizes ==="
echo "Rust: $(du -h "$RUST_BINARY" | cut -f1)"
echo "Go:   $(du -h "$GO_BINARY" | cut -f1)"

echo ""
echo "=== Running benchmarks ==="
mkdir -p target/bench

"$BENCH_BINARY" \
    --rust-binary "$RUST_BINARY" \
    --go-binary "$GO_BINARY" \
    --config config-bench.yaml \
    --dns-config config-bench-dns.yaml \
    --dns-port 15353 \
    --duration "$DURATION" \
    --output target/bench/results.json \
    ${PROXIED_ARGS[@]+"${PROXIED_ARGS[@]}"} \
    --markdown

# Standalone legs (#558): the ADR-0011 footprint collectors, then
# config-reload under live load LAST — a failed reload exits non-zero
# (a regression signal that must fail the run), and ordering it last
# keeps the footprint trend points from being skipped on that day.
echo ""
echo "=== Footprint: idle connections ==="
"$BENCH_BINARY" \
    --rust-binary "$RUST_BINARY" \
    --config config-bench.yaml \
    --only idle \
    --output target/bench/idle.json

echo ""
echo "=== Footprint: steady state ==="
"$BENCH_BINARY" \
    --rust-binary "$RUST_BINARY" \
    --config config-bench.yaml \
    --only steady \
    --duration "$DURATION" \
    --output target/bench/steady.json

# The idle leg (10k held conns) and the steady leg (tight conn churn)
# leave both ends of every loopback conn in TIME_WAIT.  macOS allocates
# ephemeral ports per local address (16k range, 2×MSL ≈ 30 s), so the
# reload leg's pre-probe can find no free port and fail before any PUT
# runs.  Linux picks ports per 4-tuple and reuses loopback TIME_WAIT
# (tcp_tw_reuse=2), so the wait is macOS-only.
if [ "$(uname -s)" = Darwin ]; then
    echo ""
    echo "=== Waiting 60s for ephemeral ports to recycle before reload ==="
    sleep 60
fi

echo ""
echo "=== Config-reload workload ==="
"$BENCH_BINARY" \
    --rust-binary "$RUST_BINARY" \
    --only reload \
    --reload-config config-bench-reload.yaml \
    --duration "$DURATION" \
    --reloads 10 \
    --output target/bench/reload.json

echo ""
echo "Results saved to target/bench/"
