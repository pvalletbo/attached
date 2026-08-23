#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s <archive.tar.xz> <target-triple>\n' "$0" >&2
  exit 64
fi

archive=$1
target=$2
archive_name=$(basename "$archive")
expected_name="attached-${target}.tar.xz"
checksum_file="${archive}.sha256"

[[ -f "$archive" ]] || { printf 'archive not found: %s\n' "$archive" >&2; exit 1; }
[[ "$archive_name" == "$expected_name" ]] || {
  printf 'unexpected archive name: got %s, expected %s\n' "$archive_name" "$expected_name" >&2
  exit 1
}
[[ -f "$checksum_file" ]] || { printf 'checksum not found: %s\n' "$checksum_file" >&2; exit 1; }

expected_checksum=$(awk 'NR == 1 { print $1 }' "$checksum_file")
[[ "$expected_checksum" =~ ^[[:xdigit:]]{64}$ ]] || {
  printf 'invalid SHA-256 checksum file: %s\n' "$checksum_file" >&2
  exit 1
}

if command -v sha256sum >/dev/null; then
  actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
else
  actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
[[ "$actual_checksum" == "$expected_checksum" ]] || {
  printf 'checksum mismatch for %s\n' "$archive_name" >&2
  exit 1
}

workspace=$(mktemp -d "${TMPDIR:-/tmp}/attached-release-archive.XXXXXX")
trap 'rm -rf "$workspace"' EXIT
tar -xJf "$archive" -C "$workspace"

binary=""
while IFS= read -r candidate; do
  if [[ -n "$binary" ]]; then
    printf 'expected exactly one executable in %s\n' "$archive_name" >&2
    exit 1
  fi
  binary=$candidate
done < <(find "$workspace" -type f -name attached -perm -u+x -print)
[[ -n "$binary" ]] || {
  printf 'expected exactly one executable in %s\n' "$archive_name" >&2
  exit 1
}

bundle_root=$(dirname "$binary")
for required in LICENSE README.md; do
  [[ -f "$bundle_root/$required" ]] || {
    printf 'missing %s next to executable in %s\n' "$required" "$archive_name" >&2
    exit 1
  }
done

version_output=$("$binary" --version)
[[ "$version_output" == attached\ * ]] || {
  printf 'unexpected version output from %s\n' "$archive_name" >&2
  exit 1
}

printf 'verified %s for %s\n' "$archive_name" "$target"
