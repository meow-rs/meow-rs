#!/usr/bin/env bash
# Print the body of CHANGELOG.md's `## [VERSION]` section (everything up to
# the next `## [` heading, surrounding blank lines trimmed). Fails when the
# section is missing or empty. Used for the GitHub Release notes and by the
# release workflows to check that a version was actually cut.
#
# Usage:
#   scripts/release/changelog-section.sh VERSION [CHANGELOG]

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release/changelog-section.sh VERSION [CHANGELOG]

Print the CHANGELOG section for VERSION (X.Y.Z, no leading "v").
CHANGELOG defaults to CHANGELOG.md at the repository root.
EOF
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
esac
[ $# -ge 1 ] && [ $# -le 2 ] || {
  usage >&2
  exit 2
}

version=$1
changelog=${2:-$(git rev-parse --show-toplevel)/CHANGELOG.md}
[ -f "$changelog" ] || {
  echo "error: $changelog not found" >&2
  exit 1
}

status=0
awk -v heading="## [$version]" '
  index($0, heading) == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found { lines[++n] = $0 }
  END {
    first = 1
    while (first <= n && lines[first] !~ /[^[:space:]]/) first++
    last = n
    while (last >= first && lines[last] !~ /[^[:space:]]/) last--
    if (first > last) exit 1
    for (i = first; i <= last; i++) print lines[i]
  }
' "$changelog" || status=$?
if [ "$status" -eq 1 ]; then
  echo "error: $changelog has no non-empty [$version] section" >&2
fi
exit "$status"
