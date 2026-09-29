#!/usr/bin/env bash
# Static and configuration-editor validation of the luci-app-meow package.
#
# No device or container needed: parses every client-side view (LuCI wraps each
# file in a function at load time, so top-level `return` is valid — we validate
# the same way), validates the menu + ACL JSON, and cross-checks the wiring:
#   - every menu "view" entry points at a view file that exists
#   - every view file is reachable from a menu entry (no orphans)
#   - every `require tools.<x>` has its shared module present
#   - ACL exec/file grants for the package's own scripts reference files the
#     package actually ships (and build-ipk.sh installs them)
#
# Catches the mistakes that a files-only ipk check misses: a JS syntax error, a
# menu path typo, an ACL grant for a script that was renamed or never packaged.
#
# Requirements: node (JS syntax) and jq (JSON). Missing tooling SKIPs.
# Usage: bash tests/test_luci_meow.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP="$ROOT/openwrt/luci-app-meow"
RES="$APP/htdocs/luci-static/resources"
VIEWS="$RES/view/meow"
MENU="$APP/root/usr/share/luci/menu.d/luci-app-meow.json"
ACL="$APP/root/usr/share/rpcd/acl.d/luci-app-meow.json"
FILES="$ROOT/openwrt/meow/files"
BUILD="$ROOT/openwrt/build-ipk.sh"

PASS=0; FAIL=0
pass() { echo "TEST_PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "TEST_FAIL: $1 ${2:+-- $2}"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP: $1"; exit 0; }

command -v node >/dev/null 2>&1 || skip "node not found (needed to parse LuCI views)"
command -v jq   >/dev/null 2>&1 || skip "jq not found (needed to validate LuCI JSON)"
[ -d "$APP" ] || skip "luci-app-meow not found at $APP"

# --- 1. Every view + shared module parses (wrapped like LuCI loads it) ---
js_ok() {
    node -e 'new Function(require("fs").readFileSync(process.argv[1],"utf8"))' "$1" 2>/dev/null
}
for f in "$RES"/tools/*.js "$VIEWS"/*.js; do
    [ -e "$f" ] || continue
    if js_ok "$f"; then pass "JS parses: ${f#$APP/}"
    else fail "JS parses: ${f#$APP/}" "$(node -e 'new Function(require("fs").readFileSync(process.argv[1],"utf8"))' "$f" 2>&1 | head -1)"; fi
done

# --- 2. Menu + ACL are valid JSON ---
jq -e . "$MENU" >/dev/null 2>&1 && pass "menu.d is valid JSON" || fail "menu.d is valid JSON"
jq -e . "$ACL"  >/dev/null 2>&1 && pass "acl.d is valid JSON"  || fail "acl.d is valid JSON"

# --- 3. Menu "view" entries <-> view files (both directions) ---
# paths referenced by view-type menu entries (action.path like "meow/overview")
menu_views="$(jq -r '.[] | select(.action.type=="view") | .action.path' "$MENU" 2>/dev/null | sort -u)"
for p in $menu_views; do
    base="${p#meow/}"
    if [ -f "$VIEWS/$base.js" ]; then pass "menu view '$p' has a view file"
    else fail "menu view '$p' has a view file" "missing $VIEWS/$base.js"; fi
done
# every view file is reachable from a menu entry
for f in "$VIEWS"/*.js; do
    base="$(basename "$f" .js)"
    if printf '%s\n' $menu_views | grep -qx "meow/$base"; then pass "view '$base' is in the menu"
    else fail "view '$base' is in the menu" "no menu.d entry points at meow/$base"; fi
done

# --- 4. Menu + views declare the ACL depend, and the ACL group exists ---
acl_group="$(jq -r 'keys[0]' "$ACL" 2>/dev/null)"
[ "$acl_group" = "luci-app-meow" ] && pass "ACL group named luci-app-meow" || fail "ACL group named luci-app-meow" "got '$acl_group'"
jq -e '.[].depends.acl // [] | index("luci-app-meow")' "$MENU" >/dev/null 2>&1 \
    && pass "menu depends on the ACL group" || fail "menu depends on the ACL group"

# --- 5. require tools.<x> modules exist ---
for mod in $(grep -rhoE "tools\.[a-zA-Z0-9_]+" "$VIEWS" 2>/dev/null | sed "s/tools\.//" | sort -u); do
    if [ -f "$RES/tools/$mod.js" ]; then pass "tools.$mod module present"
    else fail "tools.$mod module present" "missing $RES/tools/$mod.js"; fi
done

# --- 6. ACL exec/file grants for the package's own scripts point at shipped files ---
# Map a runtime path the ACL references -> the package source that installs it.
# Indexed pairs also work with macOS's Bash 3.2.
SHIP=(
    /usr/libexec/meow-api "$APP/root/usr/libexec/meow-api"
    /usr/libexec/meow-validate "$APP/root/usr/libexec/meow-validate"
    /usr/share/meow/gateway.sh "$FILES/gateway.sh"
    /usr/share/meow/arp-hijack.sh "$FILES/arp-hijack.sh"
    /etc/init.d/meow "$FILES/meow.init"
    /etc/init.d/meow-arp "$FILES/meow-arp.init"
)
# Pull the first token (the binary/script path) out of every exec-grant key.
acl_exec_paths="$(jq -r '
    [ .[].read.file, .[].write.file ] | map(select(. != null)) | add // {}
    | to_entries[] | select(.value | index("exec")) | .key
' "$ACL" 2>/dev/null | awk '{print $1}' | sort -u)"
for ((i = 0; i < ${#SHIP[@]}; i += 2)); do
    rt="${SHIP[$i]}"
    src="${SHIP[$((i + 1))]}"
    if printf '%s\n' $acl_exec_paths | grep -qx "$rt"; then
        [ -f "$src" ] && pass "ACL exec '$rt' is shipped" || fail "ACL exec '$rt' is shipped" "source $src missing"
    fi
done

# --- 7. build-ipk.sh installs the scripts the ACL/menu rely on ---
for s in gateway.sh arp-hijack.sh meow-arp.init; do
    grep -q "$s" "$BUILD" && pass "build-ipk installs $s" || fail "build-ipk installs $s"
done

# --- 8. Configuration editor request and failure handling ---
if node --test "$SCRIPT_DIR/luci_config_test.cjs" "$SCRIPT_DIR/luci_settings_test.cjs" "$SCRIPT_DIR/luci_runtime_test.cjs" "$SCRIPT_DIR/luci_clients_test.cjs"; then
    pass "configuration editor regression tests"
else
    fail "configuration editor regression tests"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ] && { echo "=== All luci-app-meow static tests passed ==="; exit 0; }
echo "=== FAIL ==="; exit 1
