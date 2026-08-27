#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s <patch|minor|major>\n' "$(basename "$0")" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 64
fi

bump=$1
case "$bump" in
  patch|minor|major) ;;
  *)
    printf 'invalid version bump: %s\n' "$bump" >&2
    usage
    exit 64
    ;;
esac

if ! command -v gh >/dev/null 2>&1; then
  printf 'GitHub CLI (gh) is required.\n' >&2
  exit 127
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

default_branch=$(gh repo view --json defaultBranchRef --jq '.defaultBranchRef.name')
repo_url=$(gh repo view --json url --jq '.url')

gh workflow run cut-release.yml \
  --ref "$default_branch" \
  --field "bump=$bump"

printf 'Triggered a %s release from %s.\n' "$bump" "$default_branch"
printf 'Follow the run at %s/actions/workflows/cut-release.yml\n' "$repo_url"
