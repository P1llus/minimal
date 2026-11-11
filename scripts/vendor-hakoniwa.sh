#!/usr/bin/env bash
# Regenerate vendor/hakoniwa/crate: the hakoniwa crate (souk4711/hakoniwa) at
# the commit pinned in vendor/hakoniwa/hakoniwa.lock, plus every patch in
# vendor/hakoniwa/patches/ applied in sorted order.
#
# The generated tree is committed, because cargo resolves a path dependency
# before any script can run. The patches are written against the upstream
# repository layout, so each one applies upstream with `git am` as it is.
#
# Usage:
#   scripts/vendor-hakoniwa.sh           rewrite vendor/hakoniwa/crate
#   scripts/vendor-hakoniwa.sh --check   fail if the committed tree differs
#
# Environment:
#   HAKONIWA_SRC   a local clone to fetch the pinned commit from, instead of
#                  the upstream repository
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/vendor/hakoniwa/hakoniwa.lock"
PATCHES="$ROOT/vendor/hakoniwa/patches"
CRATE="$ROOT/vendor/hakoniwa/crate"
REPO="${HAKONIWA_SRC:-https://github.com/souk4711/hakoniwa.git}"

die() { echo "vendor-hakoniwa: $*" >&2; exit 1; }

check=0
case "${1:-}" in
  "") ;;
  --check) check=1 ;;
  *) echo "usage: vendor-hakoniwa.sh [--check]" >&2; exit 2 ;;
esac

[ -f "$LOCK" ] || die "no lock file at $LOCK"
lock_value() { sed -n "s/^$1=//p" "$LOCK"; }
VERSION="$(lock_value version)"
COMMIT="$(lock_value commit)"
if [ -z "$VERSION" ] || [ -z "$COMMIT" ]; then
  die "malformed $LOCK: need version= and commit= lines"
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# A patch edited without the lock, or the lock without the patch, stops here.
patches=()
while IFS= read -r patch; do
  name="$(basename "$patch")"
  want="$(lock_value "patch.$name")"
  [ -n "$want" ] || die "$name has no digest in $LOCK"
  got="$(sha256_of "$patch")"
  [ "$got" = "$want" ] || die "$name digest is $got, the lock says $want"
  patches+=("$patch")
done < <(find "$PATCHES" -name '*.patch' | sort)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git init -q "$work/src"
git -C "$work/src" fetch -q --depth 1 "$REPO" "$COMMIT" \
  || git -C "$work/src" fetch -q "$REPO" "$COMMIT" \
  || die "could not fetch $COMMIT from $REPO"
git -C "$work/src" checkout -q FETCH_HEAD
[ "$(git -C "$work/src" rev-parse HEAD)" = "$COMMIT" ] || die "fetched commit is not $COMMIT"
for patch in "${patches[@]}"; do
  git -C "$work/src" apply --whitespace=nowarn "$patch" || die "$(basename "$patch") does not apply"
done

# What the published crate holds: the sources, the manifest and the licence.
mkdir "$work/crate"
cp -R "$work/src/hakoniwa/src" "$work/crate/src"
cp "$work/src/hakoniwa/Cargo.toml" "$work/src/hakoniwa/LICENSE" "$work/crate/"

if [ "$check" -eq 1 ]; then
  diff -r "$work/crate" "$CRATE" >/dev/null \
    || die "vendor/hakoniwa/crate differs from $VERSION plus the patches; run scripts/vendor-hakoniwa.sh"
  echo "vendor-hakoniwa: vendor/hakoniwa/crate matches $VERSION plus ${#patches[@]} patch(es)"
else
  rm -rf "$CRATE"
  cp -R "$work/crate" "$CRATE"
  echo "vendor-hakoniwa: wrote vendor/hakoniwa/crate from $VERSION plus ${#patches[@]} patch(es)"
fi
