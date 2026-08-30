#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
script=$repo_root/scripts/update-release-notes.sh
fixture=$(mktemp -d "${TMPDIR:-/tmp}/attached-release-notes-test.XXXXXX")
trap 'rm -rf "$fixture"' EXIT

fake_bin=$fixture/bin
mkdir -p "$fake_bin"
cat > "$fake_bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail

{
  printf '%s' "$1"
  argument_index=0
  for argument in "$@"; do
    argument_index=$((argument_index + 1))
    if [[ $argument_index -gt 1 ]]; then
      printf '\t%s' "$argument"
    fi
  done
  printf '\n'
} >> "$FAKE_GH_LOG"

command_name=${1:-}
case "$command_name" in
  api)
    if [[ ${FAKE_GH_API_FAIL:-0} == 1 ]]; then
      exit 42
    fi
    cat "$FAKE_GH_GENERATED"
    ;;
  release)
    subcommand=${2:-}
    case "$subcommand" in
      view)
        cat "$FAKE_GH_EXISTING"
        ;;
      edit)
        notes_file=
        previous=
        for argument in "$@"; do
          if [[ "$previous" == --notes-file ]]; then
            notes_file=$argument
            break
          fi
          previous=$argument
        done
        if [[ -z "$notes_file" ]]; then
          printf 'fake gh: --notes-file was not provided\n' >&2
          exit 2
        fi
        cp "$notes_file" "$FAKE_GH_EDITED"
        ;;
      *)
        printf 'fake gh: unsupported release subcommand: %s\n' "$subcommand" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    printf 'fake gh: unsupported command: %s\n' "$command_name" >&2
    exit 2
    ;;
esac
FAKE_GH
chmod +x "$fake_bin/gh"

export PATH="$fake_bin:$PATH"
export GITHUB_REPOSITORY=example/attached
export FAKE_GH_LOG=$fixture/gh.log
export FAKE_GH_GENERATED=$fixture/generated.md
export FAKE_GH_EXISTING=$fixture/existing.md
export FAKE_GH_EDITED=$fixture/edited.md

tests_run=0

fail() {
  printf 'not ok - %s\n' "$1" >&2
  exit 1
}

assert_files_equal() {
  expected=$1
  actual=$2
  if ! diff -u "$expected" "$actual"; then
    fail "files differ: $expected and $actual"
  fi
}

reset_fixture() {
  : > "$FAKE_GH_LOG"
  rm -f "$FAKE_GH_EDITED"
  unset FAKE_GH_API_FAIL || true
}

run_test() {
  name=$1
  shift
  "$@"
  tests_run=$((tests_run + 1))
  printf 'ok %d - %s\n' "$tests_run" "$name"
}

test_combines_generated_and_dist_notes() {
  reset_fixture
  cat > "$FAKE_GH_GENERATED" <<'EOF_GENERATED'
## What's Changed

* Added a useful feature
EOF_GENERATED
  cat > "$FAKE_GH_EXISTING" <<'EOF_EXISTING'
## Install attached 1.2.3

Install and artifact details.
EOF_EXISTING

  output=$("$script" v1.2.3)
  [[ "$output" == 'Added GitHub-generated release notes to v1.2.3.' ]] || \
    fail "unexpected script output: $output"

  expected=$fixture/expected.md
  cat > "$expected" <<'EOF_EXPECTED'
<!-- attached:generated-release-notes:start -->
## What's Changed

* Added a useful feature

<!-- attached:generated-release-notes:end -->

## Install attached 1.2.3

Install and artifact details.
EOF_EXPECTED
  assert_files_equal "$expected" "$FAKE_GH_EDITED"

  api_call=$(printf 'api\t--method\tPOST\trepos/example/attached/releases/generate-notes\t--raw-field\ttag_name=v1.2.3')
  grep -F "$api_call" "$FAKE_GH_LOG" > /dev/null || fail 'release-notes API was not called'
  grep -F $'release\tedit\tv1.2.3\t--repo\texample/attached\t--notes-file' \
    "$FAKE_GH_LOG" > /dev/null || fail 'release was not edited'
}

test_replaces_generated_section_on_retry() {
  reset_fixture
  cat > "$FAKE_GH_GENERATED" <<'EOF_GENERATED'
## What's Changed

* Replacement change
EOF_GENERATED
  cat > "$FAKE_GH_EXISTING" <<'EOF_EXISTING'
<!-- attached:generated-release-notes:start -->
## What's Changed

* Stale change

<!-- attached:generated-release-notes:end -->

## Install attached 1.2.3

Install and artifact details.
EOF_EXISTING

  "$script" v1.2.3 > /dev/null

  [[ $(grep -c '<!-- attached:generated-release-notes:start -->' "$FAKE_GH_EDITED") -eq 1 ]] || \
    fail 'generated notes start marker was duplicated'
  grep -F '* Replacement change' "$FAKE_GH_EDITED" > /dev/null || \
    fail 'replacement notes are missing'
  if grep -F '* Stale change' "$FAKE_GH_EDITED" > /dev/null; then
    fail 'stale generated notes were retained'
  fi
  grep -F 'Install and artifact details.' "$FAKE_GH_EDITED" > /dev/null || \
    fail 'cargo-dist notes were not retained'
}

test_rejects_malformed_markers() {
  reset_fixture
  printf '## Generated\n' > "$FAKE_GH_GENERATED"
  cat > "$FAKE_GH_EXISTING" <<'EOF_EXISTING'
<!-- attached:generated-release-notes:start -->
unterminated notes
EOF_EXISTING

  if "$script" v1.2.3 > /dev/null 2>&1; then
    fail 'malformed markers were accepted'
  fi
  [[ ! -e "$FAKE_GH_EDITED" ]] || fail 'release was edited after malformed markers'
}

test_does_not_edit_when_generation_fails() {
  reset_fixture
  : > "$FAKE_GH_GENERATED"
  printf 'existing\n' > "$FAKE_GH_EXISTING"
  export FAKE_GH_API_FAIL=1

  status=0
  "$script" v1.2.3 > /dev/null 2>&1 || status=$?
  [[ $status -eq 42 ]] || fail "expected API status 42, got $status"
  [[ ! -e "$FAKE_GH_EDITED" ]] || fail 'release was edited after API failure'
}

test_validates_release_context() {
  reset_fixture
  if "$script" latest > /dev/null 2>&1; then
    fail 'invalid release tag was accepted'
  fi

  status=0
  GITHUB_REPOSITORY=invalid "$script" v1.2.3 > /dev/null 2>&1 || status=$?
  [[ $status -eq 64 ]] || fail "expected invalid repository status 64, got $status"
  [[ ! -e "$FAKE_GH_EDITED" ]] || fail 'release was edited with invalid context'
}

run_test 'combines generated and cargo-dist notes' test_combines_generated_and_dist_notes
run_test 'replaces generated notes when retried' test_replaces_generated_section_on_retry
run_test 'rejects malformed generated-note markers' test_rejects_malformed_markers
run_test 'stops when GitHub note generation fails' test_does_not_edit_when_generation_fails
run_test 'validates the release tag and repository' test_validates_release_context

printf '1..%d\n' "$tests_run"
