#!/usr/bin/env bash
set -euo pipefail

# This installer is intentionally small and readable: Omarchy plugins are plain
# folders under ~/.config/omarchy/plugins, then the running shell is told to
# rescan and enable the plugin.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_dir="$script_dir/pvalletbo.attached"
config_home=${XDG_CONFIG_HOME:-"$HOME/.config"}
destination="$config_home/omarchy/plugins/pvalletbo.attached"
bindings="$config_home/hypr/bindings.lua"
marker='-- BEGIN Attached session picker'
end_marker='-- END Attached session picker'
managed_checksum='.attached-plugin-checksums'
plugin_files=(manifest.json Overlay.qml SessionModel.js)

binding_block() {
  printf '%s\n' "$marker"
  printf '%s\n' '-- o.bind registers a compositor-wide shortcut in Omarchy.'
  printf '%s\n' '-- The command toggles the plugin by its manifest id; edit the key chord if it conflicts.'
  printf '%s\n' 'o.bind('
  printf '%s\n' '  "SUPER + CTRL + SHIFT + H",'
  printf '%s\n' '  "Attached sessions",'
  printf '%s\n' '  "omarchy-shell shell toggle pvalletbo.attached"'
  printf '%s\n' ')'
  printf '%s\n' "$end_marker"
}

for command in omarchy omarchy-shell; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'Required Omarchy command not found: %s\n' "$command" >&2
    exit 1
  }
done

# Omarchy's validator checks the manifest, entry point, namespace and symlinks
# before any user configuration is changed.
omarchy plugin validate "$source_dir"

if [[ -L "$destination" ]]; then
  printf 'Refusing to install through a symlink: %s\n' "$destination" >&2
  exit 1
fi
if [[ -e "$destination" && ! -d "$destination" ]]; then
  printf 'Refusing to replace a non-directory plugin path: %s\n' "$destination" >&2
  exit 1
fi
if [[ -d "$destination" ]]; then
  for file in "${plugin_files[@]}" "$managed_checksum"; do
    if [[ -L "$destination/$file" ]]; then
      printf 'Refusing to replace a symlinked plugin file: %s\n' "$destination/$file" >&2
      exit 1
    fi
  done

  unexpected_entry=""
  while IFS= read -r entry; do
    filename=${entry##*/}
    managed_name=false
    for file in "${plugin_files[@]}" "$managed_checksum"; do
      [[ $filename == "$file" ]] && managed_name=true
    done
    if [[ $managed_name != true ]]; then
      unexpected_entry=$entry
      break
    fi
  done < <(find "$destination" -mindepth 1 -maxdepth 1 -print)
  if [[ -n $unexpected_entry ]]; then
    printf 'Refusing to overwrite an existing plugin with an unmanaged entry: %s\n' "$unexpected_entry" >&2
    exit 1
  fi

  existing=false
  for file in "${plugin_files[@]}"; do
    [[ -e "$destination/$file" ]] && existing=true
  done
  if [[ $existing == true && ! -f "$destination/$managed_checksum" ]]; then
    printf 'Refusing to overwrite an existing plugin not managed by this installer: %s\n' "$destination" >&2
    exit 1
  fi
  if [[ -f "$destination/$managed_checksum" ]]; then
    manifest_count=0
    overlay_count=0
    model_count=0
    checksum_valid=true
    while read -r digest filename extra || [[ -n ${digest:-}${filename:-}${extra:-} ]]; do
      if [[ ! $digest =~ ^[[:xdigit:]]{64}$ || -z ${filename:-} || -n ${extra:-} ]]; then
        checksum_valid=false
        break
      fi
      case $filename in
        manifest.json) manifest_count=$((manifest_count + 1)) ;;
        Overlay.qml) overlay_count=$((overlay_count + 1)) ;;
        SessionModel.js) model_count=$((model_count + 1)) ;;
        *) checksum_valid=false; break ;;
      esac
    done < "$destination/$managed_checksum"
    if [[ $manifest_count -ne 1 || $overlay_count -ne 1 || $model_count -ne 1 ]]; then
      checksum_valid=false
    fi
    if [[ $checksum_valid != true ]]; then
      printf 'Refusing to trust invalid plugin provenance in %s\n' "$destination/$managed_checksum" >&2
      exit 1
    fi
    if ! (cd -- "$destination" && sha256sum --check --status "$managed_checksum"); then
      printf 'Refusing to overwrite locally modified plugin files in %s\n' "$destination" >&2
      exit 1
    fi
  fi
fi

# Validate the bindings file before writing plugin files. That gives every refusal
# path a byte-exact no-write postcondition instead of leaving a partial install.
if [[ -L "$bindings" ]]; then
  printf 'Refusing to edit a symlinked bindings file: %s\n' "$bindings" >&2
  exit 1
fi
if [[ -e "$bindings" && ! -f "$bindings" ]]; then
  printf 'Refusing to edit a non-regular bindings path: %s\n' "$bindings" >&2
  exit 1
fi
begin_count=0
end_count=0
if [[ -f "$bindings" ]]; then
  begin_count=$(grep -Fxc -- "$marker" "$bindings" || true)
  end_count=$(grep -Fxc -- "$end_marker" "$bindings" || true)
fi
if [[ $begin_count != "$end_count" || $begin_count -gt 1 ]]; then
  printf 'Refusing to modify a partial or duplicate managed shortcut block in %s\n' "$bindings" >&2
  exit 1
fi
if [[ $begin_count -eq 1 ]]; then
  installed_block=""
  collecting=false
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "$marker" ]]; then
      collecting=true
    fi
    if [[ $collecting == true ]]; then
      [[ -z $installed_block ]] || installed_block+=$'\n'
      installed_block+=$line
    fi
    if [[ $collecting == true && $line == "$end_marker" ]]; then
      collecting=false
    fi
  done < "$bindings"
  expected_block=$(binding_block)
  if [[ $installed_block != "$expected_block" ]]; then
    printf 'Refusing to overwrite a locally modified managed shortcut block in %s\n' "$bindings" >&2
    exit 1
  fi
fi

# Snapshot both managed paths before the first write. Any copy, rescan, or
# enable failure restores their byte-exact pre-install state.
backup_root=$(mktemp -d "${TMPDIR:-/tmp}/attached-omarchy-install.XXXXXX")
destination_existed=false
bindings_existed=false
if [[ -d "$destination" ]]; then
  destination_existed=true
  cp -pR "$destination" "$backup_root/plugin"
fi
if [[ -f "$bindings" ]]; then
  bindings_existed=true
  cp -p "$bindings" "$backup_root/bindings.lua"
fi
transaction_committed=false

finish_install() {
  status=$?
  trap - EXIT INT TERM
  if [[ $transaction_committed != true ]]; then
    set +e
    rm -rf -- "$destination"
    if [[ $destination_existed == true ]]; then
      install -d -m 0755 "$(dirname -- "$destination")"
      cp -pR "$backup_root/plugin" "$destination"
    fi

    rm -rf -- "$bindings"
    if [[ $bindings_existed == true ]]; then
      install -d -m 0755 "$(dirname -- "$bindings")"
      cp -p "$backup_root/bindings.lua" "$bindings"
    fi

    # Reconcile the running registry with the restored filesystem. Rollback
    # must preserve the original failure even if the shell is unavailable.
    omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
    printf 'Installation failed; restored the previous plugin and bindings.\n' >&2
  fi
  rm -rf -- "$backup_root"
  exit "$status"
}
trap finish_install EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -m 0755 "$destination"
for file in "${plugin_files[@]}"; do
  install -m 0644 "$source_dir/$file" "$destination/$file"
done
(
  cd -- "$destination"
  sha256sum "${plugin_files[@]}" > "$managed_checksum"
)

install -d -m 0755 "$(dirname -- "$bindings")"
touch "$bindings"
if [[ $begin_count -eq 0 ]]; then
  printf '\n' >> "$bindings"
  binding_block >> "$bindings"
fi

omarchy-shell shell rescanPlugins
omarchy plugin enable pvalletbo.attached
transaction_committed=true
printf 'Installed Attached picker. Press Super+Ctrl+Shift+H to open it.\n'
printf 'Attached state is unlocked through 1Password; press Ctrl+O in the picker if needed.\n'
