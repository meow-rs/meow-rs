#!/usr/bin/env bash
# verify-tproxy-test.sh — assert that meow's local-outbound transparent proxy
# actually intercepts the host's own traffic. Run AFTER verify-tproxy-setup.sh
# brings up the rig. Re-runnable (handy while iterating on a meow fix).
#
# Checks (all must pass):
#   tproxy_listener_started  — meow bound the tproxy listener
#   pf_anchor_loaded /        — the redirect rules are installed
#     nft_table_loaded
#   connection_intercepted   — with MATCH,REJECT the echo server is NOT reached
#                              (baseline proved it IS reachable without meow)
#   meow_logged_original_dst — meow recovered + logged the original destination
#
# Run as a NON-root user: macOS loop-avoidance is UID-based, so a root client
# would be bypassed and never intercepted.
set -uo pipefail

STATE_DIR="${TMPDIR:-/tmp}/meow-tproxy-verify"
STATE="$STATE_DIR/state"
[ -f "$STATE" ] || { echo "no rig found — run ./verify-tproxy-setup.sh up first" >&2; exit 2; }
# shellcheck disable=SC1090
. "$STATE"

[ "$(id -u)" != 0 ] || echo "warning: running as root — the client may be uid-bypassed and not intercepted" >&2
asroot() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

echo "== meow local-outbound tproxy test ($OS) =="

# 1. listener up
if grep -qE "TProxy listener.*started" "$LOG"; then pass "tproxy_listener_started"; else fail "tproxy_listener_started"; fi

# 2. firewall rules installed — skipped when the log shows `firewall: false`
# external management (issue #563), where meow intentionally installs nothing.
# Managed objects are per-listener-instance: nft table `meow_tproxy_<pid>_<seq>`,
# pf anchor `com.apple/com.meow.tproxy.<pid>.<seq>` (issue #621) — glob the
# whole family.
if grep -q "external firewall management" "$LOG" 2>/dev/null; then
  echo "  SKIP: firewall_loaded (external management — deployer owns rules)"
elif [ "$OS" = Darwin ]; then
  anchor_ok=""
  for a in $(asroot pfctl -a com.apple -sAnchors 2>/dev/null | grep -oE 'com\.meow\.tproxy[0-9.]*'); do
    asroot pfctl -a "com.apple/$a" -sn 2>/dev/null | grep -q rdr && anchor_ok=1
  done
  if [ -n "$anchor_ok" ]; then pass "pf_anchor_loaded"; else fail "pf_anchor_loaded"; fi
else
  if asroot nft list tables 2>/dev/null | awk '$2=="inet" && $3 ~ /^meow_tproxy/' | grep -q .; then pass "nft_table_loaded"; else fail "nft_table_loaded"; fi
fi

# 3. interception: connect as the (non-root) user; MATCH,REJECT => no echo
RESP="$(printf 'HELLO\n' | nc -w 4 "$TEST_IP" "$ECHO_PORT" 2>/dev/null || true)"
sleep 1
if printf '%s' "$RESP" | grep -q ECHO_OK; then fail "connection_intercepted (echo answered → NOT intercepted)"; else pass "connection_intercepted"; fi

# 4. meow recovered the original destination
if grep -q "$TEST_IP:$ECHO_PORT" "$LOG"; then pass "meow_logged_original_dst"; else fail "meow_logged_original_dst"; fi

echo
echo "== meow log (tail) =="; tail -6 "$LOG" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g'
echo
echo "== result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
