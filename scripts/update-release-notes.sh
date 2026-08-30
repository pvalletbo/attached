#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s <vX.Y.Z>\n' "$(basename "$0")" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 64
fi

tag=$1
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'invalid stable release tag: %s\n' "$tag" >&2
  usage
  exit 64
fi

repo=${GITHUB_REPOSITORY:-}
if [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  printf 'GITHUB_REPOSITORY must be set to owner/repository.\n' >&2
  exit 64
fi

if ! command -v gh >/dev/null 2>&1; then
  printf 'GitHub CLI (gh) is required.\n' >&2
  exit 127
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/attached-release-notes.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

generated_notes=$tmp_dir/generated.md
existing_notes=$tmp_dir/existing.md
base_notes=$tmp_dir/base.md
combined_notes=$tmp_dir/combined.md
start_marker='<!-- attached:generated-release-notes:start -->'
end_marker='<!-- attached:generated-release-notes:end -->'

gh api --method POST \
  "repos/$repo/releases/generate-notes" \
  --raw-field "tag_name=$tag" \
  --jq '.body // empty' > "$generated_notes"

if ! grep -q '[^[:space:]]' "$generated_notes"; then
  printf 'GitHub generated empty release notes for %s.\n' "$tag" >&2
  exit 1
fi

gh release view "$tag" \
  --repo "$repo" \
  --json body \
  --jq '.body // ""' > "$existing_notes"

if ! awk -v start="$start_marker" -v end="$end_marker" '
  $0 == start {
    if (inside || seen) {
      invalid = 1
      exit
    }
    inside = 1
    seen = 1
    next
  }
  $0 == end {
    if (!inside) {
      invalid = 1
      exit
    }
    inside = 0
    trim_separator = 1
    next
  }
  inside { next }
  trim_separator && /^[[:space:]]*$/ { next }
  {
    trim_separator = 0
    print
  }
  END {
    if (inside || invalid) {
      exit 1
    }
  }
' "$existing_notes" > "$base_notes"; then
  printf 'Existing release notes for %s contain malformed generated-note markers.\n' \
    "$tag" >&2
  exit 1
fi

{
  printf '%s\n' "$start_marker"
  cat "$generated_notes"
  printf '\n%s\n' "$end_marker"
  if grep -q '[^[:space:]]' "$base_notes"; then
    printf '\n'
    cat "$base_notes"
  fi
} > "$combined_notes"

gh release edit "$tag" \
  --repo "$repo" \
  --notes-file "$combined_notes" > /dev/null

printf 'Added GitHub-generated release notes to %s.\n' "$tag"
