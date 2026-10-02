#!/usr/bin/env bash
set -euo pipefail
INTEGRATION="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/attached-heeler-test.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

# Exercise the actual pinned upstream and patch, including paths with spaces.
DESTINATION="$FIXTURE/Heeler source"
bash "$INTEGRATION/prepare.sh" "$DESTINATION"
[[ "$(git -C "$DESTINATION" rev-parse HEAD)" == "$(cat "$INTEGRATION/upstream-revision")" ]]
[[ "$(git -C "$DESTINATION" branch --show-current)" == attached-ios ]]
git -C "$DESTINATION" apply --reverse --check "$INTEGRATION/heeler-attached.patch"
git -C "$DESTINATION" diff --cached --check
[[ -f "$DESTINATION/LICENSE" && -f "$DESTINATION/Heeler.xcodeproj/project.pbxproj" ]]
[[ -f "$DESTINATION/docs/guides/attached.md" ]]
[[ "$(git -C "$DESTINATION" ls-files -s scripts/build-attached.sh)" == 100755* ]]

# Refuse to overwrite even a partially prepared or locally edited checkout.
printf 'keep my work\n' > "$DESTINATION/preserve.txt"
if bash "$INTEGRATION/prepare.sh" "$DESTINATION" > "$FIXTURE/second-run.log" 2>&1; then
  echo 'Expected an existing destination to be rejected.' >&2
  exit 1
fi
[[ "$(cat "$DESTINATION/preserve.txt")" == 'keep my work' ]]
echo 'Pinned source preparation, patch application, and overwrite protection passed.'
