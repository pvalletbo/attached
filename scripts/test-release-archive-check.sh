#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
checker="$repo_root/scripts/verify-release-archive.sh"
if grep -q 'mapfile' "$checker"; then
  printf 'archive verifier must remain compatible with macOS Bash 3.2\n' >&2
  exit 1
fi
fixture=$(mktemp -d "${TMPDIR:-/tmp}/attached-release-archive-test.XXXXXX")
trap 'rm -rf "$fixture"' EXIT

root="$fixture/attached-x86_64-apple-darwin"
mkdir -p "$root"
printf '%s\n' '#!/usr/bin/env sh' 'echo "attached 0.1.0"' > "$root/attached"
chmod 755 "$root/attached"
printf '%s\n' 'MIT license fixture' > "$root/LICENSE"
printf '%s\n' '# Readme fixture' > "$root/README.md"

archive="$fixture/attached-x86_64-apple-darwin.tar.xz"
tar -cJf "$archive" -C "$fixture" "$(basename "$root")"
if command -v sha256sum >/dev/null; then
  checksum=$(sha256sum "$archive" | awk '{print $1}')
else
  checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
printf '%s  %s\n' "$checksum" "$(basename "$archive")" > "$archive.sha256"

if "$checker" "$archive" aarch64-apple-darwin; then
  printf 'checker accepted an archive for the wrong target\n' >&2
  exit 1
fi
printf '%064d  %s\n' 0 "$(basename "$archive")" > "$archive.sha256"
if "$checker" "$archive" x86_64-apple-darwin; then
  printf 'checker accepted an invalid checksum\n' >&2
  exit 1
fi
printf '%s  %s\n' "$checksum" "$(basename "$archive")" > "$archive.sha256"
"$checker" "$archive" x86_64-apple-darwin
