#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
script=$repo_root/scripts/release.sh
fixture=$(mktemp -d "${TMPDIR:-/tmp}/attached-release-test.XXXXXX")
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/bin"
cat > "$fixture/bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail

{
  argument_index=0
  for argument in "$@"; do
    argument_index=$((argument_index + 1))
    if [[ $argument_index -gt 1 ]]; then
      printf '\t'
    fi
    printf '%s' "$argument"
  done
  printf '\n'
} >> "$FAKE_GH_LOG"

if [[ ${1:-} == repo && ${2:-} == view ]]; then
  case " $* " in
    *' defaultBranchRef '*) printf 'main\n' ;;
    *' url '*) printf 'https://github.com/example/attached\n' ;;
    *)
      printf 'fake gh: unsupported repo view\n' >&2
      exit 2
      ;;
  esac
elif [[ ${1:-} == workflow && ${2:-} == run ]]; then
  exit 0
else
  printf 'fake gh: unsupported invocation\n' >&2
  exit 2
fi
FAKE_GH
chmod +x "$fixture/bin/gh"

export PATH="$fixture/bin:$PATH"
export FAKE_GH_LOG=$fixture/gh.log
: > "$FAKE_GH_LOG"

output=$("$script" minor)
expected_output=$(cat <<'EOF_EXPECTED'
Triggered a minor release from main.
Release notes will be generated from merged pull requests after publishing.
Follow the run at https://github.com/example/attached/actions/workflows/cut-release.yml
EOF_EXPECTED
)
if [[ "$output" != "$expected_output" ]]; then
  printf 'unexpected release output:\n%s\n' "$output" >&2
  exit 1
fi

expected_call=$(printf 'workflow\trun\tcut-release.yml\t--ref\tmain\t--field\tbump=minor')
grep -F "$expected_call" "$FAKE_GH_LOG" > /dev/null || {
  printf 'release workflow was not dispatched correctly\n' >&2
  exit 1
}

: > "$FAKE_GH_LOG"
status=0
"$script" invalid > /dev/null 2>&1 || status=$?
if [[ $status -ne 64 ]]; then
  printf 'expected invalid bump status 64, got %s\n' "$status" >&2
  exit 1
fi
if [[ -s "$FAKE_GH_LOG" ]]; then
  printf 'GitHub CLI was called for an invalid bump\n' >&2
  exit 1
fi

printf 'ok - release dispatch announces generated notes\n'
