#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository=$(cd -- "$script_dir/../.." && pwd -P)
bin_dir=${ATTACHED_LOCAL_BIN_DIR:-"$HOME/.local/bin"}
target_dir=${CARGO_TARGET_DIR:-"$repository/target"}
if [[ $target_dir != /* ]]; then
  target_dir="$repository/$target_dir"
fi
profile=debug
cargo_args=(build --locked --package attached)

case ${1:-} in
  "") ;;
  --release)
    profile=release
    cargo_args+=(--release)
    ;;
  *)
    printf 'Usage: %s [--release]\n' "${0##*/}" >&2
    exit 2
    ;;
esac

if [[ $bin_dir != /* ]]; then
  printf 'ATTACHED_LOCAL_BIN_DIR must be an absolute path: %s\n' "$bin_dir" >&2
  exit 1
fi
if [[ -L $bin_dir ]]; then
  printf 'Refusing to install through a symlinked binary directory: %s\n' "$bin_dir" >&2
  exit 1
fi

printf 'Building Attached (%s profile)...\n' "$profile"
(
  cd -- "$repository"
  cargo "${cargo_args[@]}"
)

built_binary="$target_dir/$profile/attached"
destination="$bin_dir/attached"
if [[ ! -f $built_binary || ! -x $built_binary ]]; then
  printf 'Cargo did not produce an executable at %s\n' "$built_binary" >&2
  exit 1
fi
if [[ -L $destination || ( -e $destination && ! -f $destination ) ]]; then
  printf 'Refusing to replace a symlink or non-regular binary: %s\n' "$destination" >&2
  exit 1
fi

install -d -m 0755 "$bin_dir"
staged_binary=$(mktemp "$bin_dir/.attached-local.XXXXXX")
cleanup() {
  if [[ -n $staged_binary ]]; then
    rm -f -- "$staged_binary"
  fi
}
trap cleanup EXIT
install -m 0755 "$built_binary" "$staged_binary"
mv -f -- "$staged_binary" "$destination"
staged_binary=""

"$script_dir/install.sh"
printf 'Local Attached build and Omarchy plugin are ready. Press Super+Ctrl+Shift+H to test.\n'
