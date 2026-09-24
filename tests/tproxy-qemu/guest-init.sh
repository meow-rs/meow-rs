#!/bin/bash
# run-tests.sh — Runs inside a privileged Docker container.
# Starts meow with tproxy config, verifies nftables rules,
# tests transparent proxy interception, and prints results.

set -uo pipefail

# Helper functions
pass() { echo "TEST_PASS:$1"; }
fail() { echo "TEST_FAIL:$1"; }

# Poll for a log line up to ~10s — a one-shot `sleep 1; grep` is a
# scheduling bet that false-fails on a stalled CI container.
wait_log() {
    local i
    for i in $(seq 1 20); do
        grep -qE "$1" "$2" 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

# meow-managed nft tables are named `meow_tproxy_<pid>_<seq>` — one per
# listener instance (issue #621), with the legacy shared `meow_tproxy`
# swept on startup. Match the whole family by glob.
meow_tables() { nft list tables 2>/dev/null | awk '$2=="inet" && ($3=="meow_tproxy" || $3 ~ /^meow_tproxy_[0-9]+_[0-9]+$/) {print $3}'; }
meow_table_present() { [ -n "$(meow_tables)" ]; }
meow_chains() { # dump the `output` chain of every meow-managed table
    local t
    for t in $(meow_tables); do nft list chain inet "$t" output 2>/dev/null; done
}

# --- Setup networking ---
ip link set lo up 2>/dev/null || true
# Add a non-loopback IP on lo for testing — traffic to this IP will be
# intercepted by nftables (loopback 127.0.0.0/8 is bypassed by design).
ip addr add 10.88.0.1/32 dev lo 2>/dev/null || true

# --- Start a TCP echo server on 10.88.0.1:9999 ---
(while true; do
    echo "ECHO_RESPONSE" | nc -l -s 10.88.0.1 -p 9999 2>/dev/null || true
done) &
ECHO_PID=$!
echo "Echo server started on 10.88.0.1:9999 (PID $ECHO_PID)"

# --- Start meow ---
meow -f /etc/meow-tproxy.yaml > /tmp/meow.log 2>&1 &
MEOW_PID=$!
echo "meow started (PID $MEOW_PID)"

# --- Wait for TProxy listener to be ready (up to 10s) ---
READY=0
for i in $(seq 1 20); do
    # Match both legacy "TProxy listener started" and current
    # "TProxy listener '<name>' started on <addr>" formats.
    if grep -qE "TProxy listener( '[^']*')? started" /tmp/meow.log 2>/dev/null; then
        READY=1
        echo "TProxy listener ready after $((i * 500))ms"
        break
    fi
    if ! kill -0 "$MEOW_PID" 2>/dev/null; then
        echo "meow exited prematurely"
        break
    fi
    sleep 0.5
done

echo ""
echo "=== Running test assertions ==="

# Test 1: tproxy_ready — TProxy listener started successfully
if [ "$READY" -eq 1 ]; then
    pass "tproxy_ready"
else
    fail "tproxy_ready"
fi

# Test 2: meow_alive — meow process is still running
if kill -0 "$MEOW_PID" 2>/dev/null; then
    pass "meow_alive"
else
    fail "meow_alive"
fi

# Test 3: nftables_table — a meow-managed table was created
if meow_table_present; then
    pass "nftables_table"
else
    fail "nftables_table"
fi

# Capture once: `producer | grep -q` lets grep exit early and SIGPIPEs the
# producer's later writes, which pipefail turns into a spurious failure.
CHAINS="$(meow_chains)"

# Test 4: nftables_redirect — redirect rule exists in the output chain
if grep -q "redirect to :7893" <<<"$CHAINS"; then
    pass "nftables_redirect"
else
    fail "nftables_redirect"
fi

# Test 5: nftables_bypass — bypass rule for upstream proxy IP (10.99.0.1) exists
if grep -q "10.99.0.1" <<<"$CHAINS"; then
    pass "nftables_bypass"
else
    fail "nftables_bypass"
fi

# Test 5b: nftables_mark — SO_MARK bypass rule exists (routing-mark: 9527 = 0x2537)
if grep -q "meta mark" <<<"$CHAINS"; then
    pass "nftables_mark"
else
    fail "nftables_mark"
fi

# Test 6: tproxy_listening — tproxy port is actually listening
if nc -z 127.0.0.1 7893 2>/dev/null; then
    pass "tproxy_listening"
else
    fail "tproxy_listening"
fi

# Test 7: tproxy_intercept — transparent proxy intercepts a TCP connection
# Connect to 10.88.0.1:9999 (non-loopback); nftables redirects through tproxy
RESPONSE=""
RESPONSE=$(echo "HELLO" | timeout 5 nc -w 3 10.88.0.1 9999 2>/dev/null) || true

# Verify meow logged the intercepted connection to 10.88.0.1:9999
if wait_log "10.88.0.1:9999" /tmp/meow.log; then
    pass "tproxy_intercept"
else
    fail "tproxy_intercept"
fi

# Test 8: tproxy_relay — data was relayed end-to-end through the proxy
if [ "$RESPONSE" = "ECHO_RESPONSE" ]; then
    pass "tproxy_relay"
else
    fail "tproxy_relay"
fi

# Test 9: tproxy_sni_extract — SNI extraction from TLS ClientHello
# Build a minimal TLS ClientHello with SNI "sni.example.com" (15 bytes)
# Lengths: SNI name=15, entry=18(3+15), list=18, ext_data=20(2+18), ext=24(4+20)
# Extensions total=24
# ClientHello body: 2+32+1+4+2+2+24 = 67 = 0x43
# Handshake: 4+67 = 71
# Record: 5+71 = 76
{
    printf '\x16\x03\x01\x00\x47'           # TLS record: handshake, len=71
    printf '\x01\x00\x00\x43'               # ClientHello, len=67
    printf '\x03\x03'                        # Version TLS 1.2
    dd if=/dev/zero bs=32 count=1 2>/dev/null  # Random (32 bytes)
    printf '\x00'                            # Session ID length: 0
    printf '\x00\x02\x00\x2f'               # Cipher suites: len=2, one suite
    printf '\x01\x00'                        # Compression: len=1, null
    printf '\x00\x18'                        # Extensions length: 24
    printf '\x00\x00'                        # SNI extension type (0x0000)
    printf '\x00\x14'                        # SNI extension data length: 20
    printf '\x00\x12'                        # Server name list length: 18
    printf '\x00'                            # Host name type: 0
    printf '\x00\x0f'                        # Host name length: 15
    printf 'sni.example.com'                # Hostname (15 bytes)
} | timeout 3 nc -w 2 10.88.0.1 443 2>/dev/null || true

if wait_log "sni.example.com" /tmp/meow.log; then
    pass "tproxy_sni_extract"
else
    fail "tproxy_sni_extract"
fi

# Test 10: firewall_teardown — stop meow, verify nftables rules cleaned up
kill -TERM "$MEOW_PID" 2>/dev/null
# Wait for process to exit (up to 5s)
for i in $(seq 1 10); do
    kill -0 "$MEOW_PID" 2>/dev/null || break
    sleep 0.5
done
# Force kill if still alive
kill -9 "$MEOW_PID" 2>/dev/null || true
sleep 1

if meow_table_present; then
    fail "firewall_teardown"
else
    pass "firewall_teardown"
fi

# ═══ Phase 2: `firewall: false` — external rule management (issue #563) ═══
#
# The deployer installs the redirect table by hand (mirroring the managed
# shape: mark/loopback/proxy-IP bypasses + catch-all redirect); meow must
# serve the intercepted traffic without creating a `meow_tproxy*` table,
# and must leave this table alone on exit.
echo ""
echo "=== External-firewall phase (firewall: false) ==="

# The ruleset below mirrors the managed table's shape — keep the magic
# numbers in sync with meow-tproxy-ext.yaml (mark 0x2537 = routing-mark
# 9527, redirect port :7894, proxy-IP bypass 10.99.0.1 = the upstream).
nft -f - <<'NFT'
table inet meow_ext_fw {
  chain output {
    type nat hook output priority -100; policy accept;
    meta mark 0x2537 accept
    ip daddr 127.0.0.0/8 accept
    ip6 daddr ::1 accept
    ip daddr 10.99.0.1 accept
    tcp dport 1-65535 redirect to :7894
  }
}
NFT

# A failed ruleset install must fail loudly here — otherwise the relay
# checks below fail indirectly and hide the deployer-side cause.
if nft list table inet meow_ext_fw >/dev/null 2>&1; then
    pass "ext_fw_installed"
else
    fail "ext_fw_installed"
fi

meow -f /etc/meow-tproxy-ext.yaml > /tmp/meow-ext.log 2>&1 &
EXT_MEOW_PID=$!
echo "meow (external fw) started (PID $EXT_MEOW_PID)"

EXT_READY=0
for i in $(seq 1 20); do
    if grep -q "TProxy listener 'ext-tproxy' started" /tmp/meow-ext.log 2>/dev/null; then
        EXT_READY=1
        echo "External-fw TProxy listener ready after $((i * 500))ms"
        break
    fi
    if ! kill -0 "$EXT_MEOW_PID" 2>/dev/null; then
        echo "meow (external fw) exited prematurely"
        break
    fi
    sleep 0.5
done

# Test 11: ext_tproxy_ready — externally-managed listener started
if [ "$EXT_READY" -eq 1 ]; then
    pass "ext_tproxy_ready"
else
    fail "ext_tproxy_ready"
fi

# Test 12: ext_no_managed_table — meow created NO nftables state for this
# listener (no meow-managed table may exist)
if meow_table_present; then
    fail "ext_no_managed_table"
else
    pass "ext_no_managed_table"
fi

# Test 13: ext_fw_log — startup log discloses external management
if grep -q "external firewall management" /tmp/meow-ext.log 2>/dev/null; then
    pass "ext_fw_log"
else
    fail "ext_fw_log"
fi

# Test 14: ext_tproxy_relay — traffic redirected by the EXTERNAL rules is
# served end-to-end (orig-dest recovery + relay through the tunnel)
EXT_RESPONSE=""
EXT_RESPONSE=$(echo "HELLO" | timeout 5 nc -w 3 10.88.0.1 9999 2>/dev/null) || true

if [ "$EXT_RESPONSE" = "ECHO_RESPONSE" ] \
    && wait_log "10.88.0.1:9999" /tmp/meow-ext.log; then
    pass "ext_tproxy_relay"
else
    fail "ext_tproxy_relay"
fi

# Test 15: ext_fw_persists — stopping meow must NOT remove the deployer's
# table (meow cleans up only what it owns)
kill -TERM "$EXT_MEOW_PID" 2>/dev/null
for i in $(seq 1 10); do
    kill -0 "$EXT_MEOW_PID" 2>/dev/null || break
    sleep 0.5
done
kill -9 "$EXT_MEOW_PID" 2>/dev/null || true
sleep 1

if nft list table inet meow_ext_fw >/dev/null 2>&1; then
    pass "ext_fw_persists"
else
    fail "ext_fw_persists"
fi

# The harness owns the external table — remove it explicitly before the
# UDP phase: the inet catch-all redirect would race phase 3's ip-family
# nat output chain on host TCP traffic.
nft delete table inet meow_ext_fw 2>/dev/null || true
if nft list table inet meow_ext_fw >/dev/null 2>&1; then
    echo "SETUP FAILURE: meow_ext_fw delete failed — phase 3 same-port test would race"
    fail "ext_fw_cleanup"
fi

# ═══ Phase 3: `udp: true` — external UDP TPROXY (issue #564) ═══
#
# UDP TPROXY only intercepts packets on the PREROUTING hook, and the
# transparent reply socket must bind the ORIGINAL destination — which must
# therefore not exist on the host. Both client and server are network
# namespaces; the host is a real router between them, and the deployer
# half of the TPROXY contract (fwmark → local-table policy routing + the
# tproxy rule) is installed by hand. TCP REDIRECT on the same listener
# port proves TCP and UDP coexist.
echo ""
echo "=== UDP TPROXY phase (udp: true) ==="

# LAN client 10.77.0.2 ←veth→ host 10.77.0.1 ←→ srv 10.89.0.254 → server
# 10.89.0.1. A distinct /24 avoids the host's loopback alias (10.88.0.1/32
# on lo) shadowing the subnet route.
ip netns add lan
ip netns add srv
ip link add veth-host type veth peer name veth-lan
ip link add veth-srv type veth peer name veth-dest
ip addr add 10.77.0.1/30 dev veth-host
ip addr add 10.89.0.254/24 dev veth-srv
ip link set veth-host up
ip link set veth-srv up
ip link set veth-lan netns lan
ip link set veth-dest netns srv
ip netns exec lan ip link set lo up
ip netns exec lan ip addr add 10.77.0.2/30 dev veth-lan
ip netns exec lan ip link set veth-lan up
ip netns exec lan ip route add default via 10.77.0.1
ip netns exec srv ip link set lo up
ip netns exec srv ip addr add 10.89.0.1/24 dev veth-dest
ip netns exec srv ip link set veth-dest up
ip netns exec srv ip route add default via 10.89.0.254

# fwmark → local delivery table (the deployer's policy-routing half).
# `ip_forward` is deliberately NOT set: the fwmark→local-table route
# converts intercepted packets to local delivery, so the data plane
# never takes the forward path — don't "fix" this by enabling it.
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# UDP echo server on the "real" destination inside srv — netcat-
# traditional's `-e cat` echoes each received datagram back to its sender.
(while true; do
    ip netns exec srv nc -u -l -s 10.89.0.1 -p 9998 -e /bin/cat 2>/dev/null || true
done) &
UDP_ECHO_PID=$!

# TCP echo server for the same-port regression (matches phase 1's shape).
(while true; do
    echo "ECHO_RESPONSE" | ip netns exec srv nc -l -s 10.89.0.1 -p 9999 2>/dev/null || true
done) &
TCP_SRV_ECHO_PID=$!

# Wait for the echo servers to actually bind — otherwise the first
# datagram is dropped before nc is listening and the test races its own
# setup.
for i in $(seq 1 20); do
    ip netns exec srv ss -uln 2>/dev/null | grep -q ':9998 ' \
        && ip netns exec srv ss -ltn 2>/dev/null | grep -q ':9999 ' && break
    sleep 0.3
done

# External rules: TPROXY steers LAN UDP datagrams for 10.89.0.1:9998 to
# meow's :7895, while an output-chain REDIRECT sends host TCP :9999 to the
# SAME port — the issue's TCP/UDP same-port requirement. The nat chain
# also pulls in nf_conntrack, which IP_ORIGDSTADDR depends on — removing
# it would silently empty every cmsg and drop all UDP flows.
nft -f - <<'NFT'
table ip meow_udp_tproxy {
  chain pre {
    type filter hook prerouting priority mangle; policy accept;
    ip daddr 10.89.0.1 udp dport 9998 tproxy ip to 127.0.0.1:7895 meta mark set 0x1 accept
  }
  chain output {
    type nat hook output priority -100; policy accept;
    meta mark 0x2537 accept
    ip daddr 127.0.0.0/8 accept
    ip daddr 10.99.0.1 accept
    tcp dport 9999 redirect to :7895
  }
}
NFT

# Preflight: if the ruleset failed to install every UDP assertion below
# fails for the wrong reason — surface it explicitly.
if ! nft list table ip meow_udp_tproxy >/dev/null 2>&1; then
    echo "SETUP FAILURE: meow_udp_tproxy nft table not installed"
    fail "udp_nft_installed"
fi

meow -f /etc/meow-tproxy-udp.yaml > /tmp/meow-udp.log 2>&1 &
UDP_MEOW_PID=$!
echo "meow (udp tproxy) started (PID $UDP_MEOW_PID)"

UDP_READY=0
for i in $(seq 1 20); do
    if grep -q "UDP TPROXY active" /tmp/meow-udp.log 2>/dev/null; then
        UDP_READY=1
        echo "UDP TPROXY listener ready after $((i * 500))ms"
        break
    fi
    if ! kill -0 "$UDP_MEOW_PID" 2>/dev/null; then
        echo "meow (udp tproxy) exited prematurely"
        break
    fi
    sleep 0.5
done

# Test 16: udp_tproxy_ready — UDP TPROXY socket bound and active
if [ "$UDP_READY" -eq 1 ]; then
    pass "udp_tproxy_ready"
else
    fail "udp_tproxy_ready"
fi

# Test 17: udp_no_managed_table — `firewall: false` still means zero
# nftables state owned by meow
if meow_table_present; then
    fail "udp_no_managed_table"
else
    pass "udp_no_managed_table"
fi

# Test 18: udp_flow_relay — a LAN client's datagram reaches the echo
# server through the tunnel AND the reply returns. `nc -u` connect()s the
# socket, so a reply only registers when its source is 10.89.0.1:9998.
# Caveat: an un-intercepted forward path would echo too — the source-
# identity proof holds only given meow-transit, which udp_flow_logged
# below establishes.
UDP_RESPONSE=""
UDP_RESPONSE=$(ip netns exec lan sh -c \
    'echo PING | timeout 5 nc -u -w3 10.89.0.1 9998' 2>/dev/null) || true

if [ "$UDP_RESPONSE" = "PING" ]; then
    pass "udp_flow_relay"
else
    fail "udp_flow_relay"
fi

# Test 19: udp_flow_logged — the flow was routed through the rule engine
# (proves dispatch → resolve_proxy, not a raw socket shortcut)
if wait_log "UDP 10\.77\.0\.2:[0-9]+ --> 10\.89\.0\.1:9998 match" /tmp/meow-udp.log; then
    pass "udp_flow_logged"
else
    fail "udp_flow_logged"
fi

# Test 20: udp_tcp_same_port — the same listener port still serves
# TCP REDIRECT'd traffic (TCP behaviour unchanged)
TCP_SAME_PORT=""
TCP_SAME_PORT=$(echo "HELLO" | timeout 5 nc -w 3 10.89.0.1 9999 2>/dev/null) || true

if [ "$TCP_SAME_PORT" = "ECHO_RESPONSE" ] \
    && wait_log "10.89.0.1:9999" /tmp/meow-udp.log; then
    pass "udp_tcp_same_port"
else
    fail "udp_tcp_same_port"
fi

# Test 21: udp_rules_persist — stopping meow must NOT remove the
# deployer's TPROXY rules or policy routing
kill -TERM "$UDP_MEOW_PID" 2>/dev/null
for i in $(seq 1 10); do
    kill -0 "$UDP_MEOW_PID" 2>/dev/null || break
    sleep 0.5
done
kill -9 "$UDP_MEOW_PID" 2>/dev/null || true
sleep 1

if nft list table ip meow_udp_tproxy >/dev/null 2>&1 \
    && ip rule show | grep -q "fwmark 0x1 lookup 100"; then
    pass "udp_rules_persist"
else
    fail "udp_rules_persist"
fi

# Dump the live ruleset BEFORE teardown — a failure above needs the
# evidence, not an empty table.
echo ""
echo "=== nftables state (pre-teardown) ==="
nft list ruleset 2>/dev/null || echo "(empty)"
echo "=== end nftables ==="

# The harness owns everything external — tear it down explicitly. Kill
# the echo loops first so a respawning `ip netns exec` can't busy-spin
# against a vanishing namespace.
kill "$UDP_ECHO_PID" "$TCP_SRV_ECHO_PID" 2>/dev/null || true
nft delete table ip meow_udp_tproxy 2>/dev/null || true
ip rule del fwmark 0x1 lookup 100 2>/dev/null || true
ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
ip netns del lan 2>/dev/null || true
ip netns del srv 2>/dev/null || true
ip link del veth-host 2>/dev/null || true
ip link del veth-srv 2>/dev/null || true

# ═══ Phase 4: per-instance ownership, stale sweep, multi-listener (issue #621) ═══
#
# Two managed listeners in one process must own DISTINCT
# `inet meow_tproxy_<pid>_<seq>` tables; a crash leaves them behind and
# the next instance sweeps exactly what a dead owner left. Objects whose
# embedded pid is a LIVE meow process are kept (a sibling owns them); a
# live pid that isn't meow is a reused-pid residue and is swept too.
echo ""
echo "=== Per-instance ownership phase (issue #621) ==="

# A live sibling meow (phase-1 config) owns `meow_tproxy_<sib>_0` — the
# keep-side of every sweep below. Its setup (and therefore its sweep)
# is done once its listener-start line lands.
meow -f /etc/meow-tproxy.yaml > /tmp/meow-sib.log 2>&1 &
SIB_PID=$!
for i in $(seq 1 20); do
    grep -qE "TProxy listener( '[^']*')? started" /tmp/meow-sib.log 2>/dev/null && break
    kill -0 "$SIB_PID" 2>/dev/null || break
    sleep 0.5
done
SIB_TABLE="meow_tproxy_${SIB_PID}_0"

# A slow/crashed sibling must be caught here — otherwise its *delayed*
# sweep could eat the plants below and sweep_on_start would attribute
# the sibling's work to the multi instance.
if ! nft list table inet "$SIB_TABLE" >/dev/null 2>&1; then
    echo "SETUP FAILURE: sibling meow table '$SIB_TABLE' absent (pid $SIB_PID)"
    fail "sibling_ready"
fi

# Plant sweep-classification objects before the multi instance starts:
#   meow_tproxy_999999_0 — dead pid           → swept
#   meow_tproxy_1_9      — live pid, not meow → swept (reused-pid residue)
#   meow_tproxy          — legacy shared name → swept
nft add table inet meow_tproxy_999999_0
nft add table inet meow_tproxy_1_9
nft add table inet meow_tproxy

# Preflight: the sweep assertions below are vacuous if any plant failed.
PLANTS_OK=1
for t in meow_tproxy_999999_0 meow_tproxy_1_9 meow_tproxy; do
    nft list table inet "$t" >/dev/null 2>&1 || PLANTS_OK=0
done
if [ "$PLANTS_OK" -eq 1 ]; then
    pass "sweep_plants_installed"
else
    echo "SETUP FAILURE: sweep plant(s) failed to install"
    fail "sweep_plants_installed"
fi

meow -f /etc/meow-tproxy-multi.yaml > /tmp/meow-multi.log 2>&1 &
MULTI_PID=$!
echo "meow (multi-listener) started (PID $MULTI_PID), sibling=$SIB_PID"

# Both listeners are independent tasks — 'tproxy-b started' alone says
# nothing about tproxy-a's setup. Poll for the outcome that matters:
# two tables owned by THIS pid (which also implies both setups ran and
# the multi-firewall warn fired).
MULTI_READY=0
for i in $(seq 1 20); do
    if [ "$(meow_tables | grep -c "_${MULTI_PID}_")" -eq 2 ]; then
        MULTI_READY=1
        break
    fi
    if ! kill -0 "$MULTI_PID" 2>/dev/null; then
        echo "meow (multi-listener) exited prematurely"
        break
    fi
    sleep 0.5
done

# Test 22: multi_tables_two — two managed listeners own two distinct tables
if [ "$MULTI_READY" -eq 1 ]; then
    pass "multi_tables_two"
else
    fail "multi_tables_two (tables: $(meow_tables | tr '\n' ' '))"
fi

# Test 23: multi_table_contents — each table redirects to a DIFFERENT
# listener port (don't bind port↔seq — assignment is lock-order dependent)
# NOTE: capture first — `meow_chains | grep -q` would SIGPIPE the loop's
# later `nft list chain` calls and pipefail turns the match into a fail.
MULTI_CHAINS=$(meow_chains)
if grep -q "redirect to :7896" <<<"$MULTI_CHAINS" \
    && grep -q "redirect to :7897" <<<"$MULTI_CHAINS"; then
    pass "multi_table_contents"
else
    fail "multi_table_contents (chains: $MULTI_CHAINS)"
fi

# Test 24: sweep_on_start — dead-pid, reused-pid, and legacy objects gone;
# the sibling's live table untouched; the log proves the sweep ran. The
# live-pid arm logs the louder `owned by a live pid` warn, not `stale`.
if ! nft list table inet meow_tproxy_999999_0 >/dev/null 2>&1 \
    && ! nft list table inet meow_tproxy_1_9 >/dev/null 2>&1 \
    && ! nft list table inet meow_tproxy >/dev/null 2>&1 \
    && nft list table inet "$SIB_TABLE" >/dev/null 2>&1 \
    && grep -q "swept stale nftables table 'meow_tproxy_999999_0'" /tmp/meow-multi.log \
    && grep -q "swept nftables table 'meow_tproxy_1_9' owned by a live pid" /tmp/meow-multi.log \
    && grep -q "swept legacy shared nftables table 'meow_tproxy'" /tmp/meow-multi.log; then
    pass "sweep_on_start"
else
    fail "sweep_on_start"
fi

# Test 25: multi_warn_logged — the ambiguity warning fired on second setup
if grep -q "multiple managed tproxy firewalls" /tmp/meow-multi.log 2>/dev/null; then
    pass "multi_warn_logged"
else
    fail "multi_warn_logged"
fi

# Test 26: crash_residue — SIGKILL leaves the tables behind (they are
# INPUT to the sweep test below, so this asserts the residue exists)
kill -9 "$MULTI_PID" 2>/dev/null || true
sleep 1
if [ "$(meow_tables | grep -c "_${MULTI_PID}_")" -eq 2 ]; then
    pass "crash_residue"
else
    fail "crash_residue"
fi

meow -f /etc/meow-tproxy-multi.yaml > /tmp/meow-multi2.log 2>&1 &
MULTI2_PID=$!
MULTI2_READY=0
for i in $(seq 1 20); do
    if [ "$(meow_tables | grep -c "_${MULTI2_PID}_")" -eq 2 ]; then
        MULTI2_READY=1
        break
    fi
    if ! kill -0 "$MULTI2_PID" 2>/dev/null; then
        echo "meow (multi2) exited prematurely"
        break
    fi
    sleep 0.5
done

# Test 27: sweep_classification — the crashed instance's tables swept
# (log-proven), the new instance created its own two, and the only
# survivor outside the new pid is the live sibling's
SURVIVORS=$(meow_tables | grep -v "_${MULTI2_PID}_" || true)
if [ "$MULTI2_READY" -eq 1 ] && [ "$SURVIVORS" = "$SIB_TABLE" ] \
    && grep -q "swept stale nftables table 'meow_tproxy_${MULTI_PID}_" /tmp/meow-multi2.log; then
    pass "sweep_classification"
else
    fail "sweep_classification (ready=$MULTI2_READY survivors: $(echo "$SURVIVORS" | tr '\n' ' '))"
fi

# Test 28: graceful_teardown_multi — SIGTERM removes THIS instance's
# tables; the sibling's table survives because its owner is alive
kill -TERM "$MULTI2_PID" 2>/dev/null
for i in $(seq 1 10); do
    kill -0 "$MULTI2_PID" 2>/dev/null || break
    sleep 0.5
done
kill -9 "$MULTI2_PID" 2>/dev/null || true
sleep 1

OWN_LEFT=$(meow_tables | grep -c "_${MULTI2_PID}_")
if [ "$OWN_LEFT" -eq 0 ] && nft list table inet "$SIB_TABLE" >/dev/null 2>&1; then
    pass "graceful_teardown_multi"
else
    fail "graceful_teardown_multi (own_left=$OWN_LEFT)"
fi

# Test 29: sibling_teardown — killing the sibling removes the last table;
# nothing meow-owned remains
kill -TERM "$SIB_PID" 2>/dev/null
for i in $(seq 1 10); do
    kill -0 "$SIB_PID" 2>/dev/null || break
    sleep 0.5
done
kill -9 "$SIB_PID" 2>/dev/null || true
sleep 1

if meow_table_present; then
    fail "sibling_teardown ($(meow_tables | tr '\n' ' '))"
else
    pass "sibling_teardown"
fi

# --- Debug output ---
echo ""
echo "=== meow log ==="
cat /tmp/meow.log 2>/dev/null || echo "(no log)"
echo "=== end log ==="
echo ""
echo "=== meow log (external fw) ==="
cat /tmp/meow-ext.log 2>/dev/null || echo "(no log)"
echo "=== end log ==="
echo ""
echo "=== meow log (udp tproxy) ==="
cat /tmp/meow-udp.log 2>/dev/null || echo "(no log)"
echo "=== end log ==="
echo ""
echo "=== meow log (multi-listener, first run) ==="
cat /tmp/meow-multi.log 2>/dev/null || echo "(no log)"
echo "=== end log ==="
echo ""
echo "=== meow log (multi-listener, after kill -9) ==="
cat /tmp/meow-multi2.log 2>/dev/null || echo "(no log)"
echo "=== end log ==="

# Cleanup
kill "$ECHO_PID" 2>/dev/null || true
