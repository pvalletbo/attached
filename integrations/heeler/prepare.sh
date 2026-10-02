#!/usr/bin/env bash
# Produce the complete, reviewable Heeler source for local Mac/device builds.
set -euo pipefail

INTEGRATION="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$INTEGRATION/../.." && pwd)"
if [[ "${1:-}" == --help ]]; then
  cat <<'HELP'
Usage: bash integrations/heeler/prepare.sh [new-checkout-directory]

Fetches a pinned ZingerLittleBee/Heeler source revision, creates a local
attached-ios branch, and stages the Attached integration patch for review.
The destination must not exist; the default is target/Heeler in Attached.

On a Mac with full Xcode 26+, XcodeGen 2.46+, and rustup, enter the resulting
checkout and run make attached-client, then make build-sim. Open
Heeler.xcodeproj and choose your signing team to run on an iPhone or iPad.
Read docs/guides/attached.md in that checkout for publisher setup and tests.
HELP
  exit 0
fi
[[ $# -le 1 ]] || { echo 'Expected at most one destination argument.' >&2; exit 1; }
REVISION="$(tr -d '\n' < "$INTEGRATION/upstream-revision")"
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid Heeler revision pin.' >&2; exit 1; }
DESTINATION="${1:-$ROOT/target/Heeler}"
[[ ! -e "$DESTINATION" && ! -L "$DESTINATION" ]] || {
  echo 'Destination already exists; choose a new directory to preserve its contents.' >&2
  exit 1
}
mkdir -p "$(dirname "$DESTINATION")"
mkdir "$DESTINATION"
DESTINATION="$(cd "$DESTINATION" && pwd)"
git -C "$DESTINATION" init
git -C "$DESTINATION" remote add upstream https://github.com/ZingerLittleBee/Heeler.git
git -C "$DESTINATION" fetch --depth 1 upstream "$REVISION"
git -C "$DESTINATION" checkout -b attached-ios "$REVISION"
git -C "$DESTINATION" apply --check "$INTEGRATION/heeler-attached.patch"
git -C "$DESTINATION" apply --index "$INTEGRATION/heeler-attached.patch"
printf '\nHeeler source ready at: %s\n' "$DESTINATION"
printf '%s\n' 'Changes are staged for review with git diff --cached.' \
  'Next on macOS: make attached-client && make build-sim' \
  'Setup and device testing: docs/guides/attached.md'
