#!/usr/bin/env bash
# Stage a release in the working tree: bump the lockstep workspace version
# (and every internal `path` dependency pin that repeats it), refresh
# Cargo.lock, and cut CHANGELOG.md's [Unreleased] section under a dated
# `## [X.Y.Z]` heading. Commits nothing. Run by
# .github/workflows/prepare-release.yml; works locally the same way.
#
# Usage:
#   scripts/release/prepare.sh [VERSION]
#
# Without VERSION the bump is inferred from the conventional-commit messages
# since the tag of the current version (v<current>):
#   - a breaking change (`type!:` subject or `BREAKING CHANGE:` footer):
#     major from 1.0, minor before it
#   - any `feat`: minor
#   - otherwise: patch
#
# Environment:
#   RELEASE_DATE   heading date (default: today, UTC)
#   GITHUB_OUTPUT  if set, `version=` / `previous=` are appended to it
#
# See docs/RELEASING.md.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release/prepare.sh [VERSION]

Bump the workspace to VERSION (X.Y.Z), refresh Cargo.lock and cut the
CHANGELOG.md [Unreleased] section. Omit VERSION to infer it from the
commits since the current version's tag.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
esac
[ $# -le 1 ] || {
  usage >&2
  exit 2
}

cd "$(git rev-parse --show-toplevel)"

# `sed -i` differs between GNU and BSD sed; go through a temp file instead.
sed_inplace() {
  local expr=$1 file=$2
  sed -E "$expr" "$file" >"$file.tmp"
  mv "$file.tmp" "$file"
}

workspace_version() {
  sed -nE '/^\[workspace\.package\]/,/^\[/ s/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' Cargo.toml | head -n1
}

version_gt() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]
}

cur=$(workspace_version)
[ -n "$cur" ] || die "could not parse [workspace.package] version from Cargo.toml"

new=${1:-}
if [ -z "$new" ]; then
  prev_tag="v$cur"
  git rev-parse -q --verify "refs/tags/$prev_tag" >/dev/null ||
    die "tag $prev_tag not found (fetch tags, or pass VERSION explicitly)"
  log=$(git log --format='%s%n%b' "$prev_tag..HEAD")
  [ -n "$log" ] || die "no commits since $prev_tag; nothing to release"

  bump="patch"
  if grep -qE '^feat(\([^)]*\))?!?:' <<<"$log"; then
    bump="minor"
  fi
  if grep -qE '^[a-z]+(\([^)]*\))?!:|^BREAKING[ -]CHANGE:' <<<"$log"; then
    bump="major"
  fi

  IFS=. read -r major minor patch <<<"$cur"
  if [ "$bump" = major ] && [ "$major" -eq 0 ]; then
    bump="minor"
  fi
  case "$bump" in
    major) new="$((major + 1)).0.0" ;;
    minor) new="$major.$((minor + 1)).0" ;;
    patch) new="$major.$minor.$((patch + 1))" ;;
  esac
  echo "Inferred $bump bump from $(git rev-list --count "$prev_tag..HEAD") commit(s) since $prev_tag."
fi

[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must be X.Y.Z, got '$new'"
version_gt "$new" "$cur" || die "VERSION $new must be greater than the current $cur"

git diff --quiet HEAD -- Cargo.toml Cargo.lock CHANGELOG.md ':(glob)crates/*/Cargo.toml' ||
  die "Cargo manifests, Cargo.lock or CHANGELOG.md have uncommitted changes"
if git rev-parse -q --verify "refs/tags/v$new" >/dev/null; then
  die "tag v$new already exists"
fi
if grep -qF "## [$new]" CHANGELOG.md; then
  die "CHANGELOG.md already has a [$new] section"
fi

# --- CHANGELOG.md: the curated [Unreleased] entries become the release notes.
unreleased=$(awk '
  /^## \[Unreleased\]/ { found = 1; next }
  found && /^## \[/ { exit }
  found && NF { n++ }
  END { print found ? n + 0 : -1 }
' CHANGELOG.md)
[ "$unreleased" -ge 0 ] || die "CHANGELOG.md has no '## [Unreleased]' heading"
[ "$unreleased" -gt 0 ] || die "CHANGELOG.md [Unreleased] is empty; record the user-visible changes first"

date=${RELEASE_DATE:-$(date -u +%Y-%m-%d)}
[[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "RELEASE_DATE must be YYYY-MM-DD, got '$date'"

# Keep an empty [Unreleased] heading on top and insert the release heading
# right below it, so the cut moves no existing lines.
awk -v heading="## [$new] - $date" '
  state == 1 && !NF { next }
  state == 1 { print heading; print ""; state = 2 }
  { print }
  /^## \[Unreleased\]/ && state == 0 { print ""; state = 1 }
' CHANGELOG.md >CHANGELOG.md.tmp
mv CHANGELOG.md.tmp CHANGELOG.md

# --- Versions. Every crate inherits `version.workspace = true` except the
# vendored meow-anytls, which spells it out; internal path deps repeat the
# version because crates.io requires one.
cur_re=${cur//./\\.}
sed_inplace "/^\[workspace\.package\]/,/^\[/ s/^version = \"$cur_re\"/version = \"$new\"/" Cargo.toml
for manifest in Cargo.toml crates/*/Cargo.toml; do
  sed_inplace "/path = \"[^\"]*meow-[a-z0-9-]+\"/ s/version = \"$cur_re\"/version = \"$new\"/" "$manifest"
  if [ "$manifest" != Cargo.toml ]; then
    sed_inplace "/^\[package\]/,/^\[/ s/^version = \"$cur_re\"/version = \"$new\"/" "$manifest"
  fi
done

[ "$(workspace_version)" = "$new" ] || die "failed to bump [workspace.package] version"
if stale=$(grep -nE "path = \"[^\"]*meow-[a-z0-9-]+\".*version = \"$cur_re\"|^version = \"$cur_re\"" \
  Cargo.toml crates/*/Cargo.toml); then
  die "manifest lines still at $cur:"$'\n'"$stale"
fi

cargo update --workspace --quiet

echo "Prepared release $new (from $cur, dated $date)."
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "version=$new"
    echo "previous=$cur"
  } >>"$GITHUB_OUTPUT"
fi
