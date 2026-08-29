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
if [[ -d "$destination" ]]; then
  for file in "${plugin_files[@]}" "$managed_checksum"; do
    if [[ -L "$destination/$file" ]]; then
      printf 'Refusing to replace a symlinked plugin file: %s\n' "$destination/$file" >&2
      exit 1
    fi
  done

  existing=false
  for file in "${plugin_files[@]}"; do
    [[ -e "$destination/$file" ]] && existing=true
  done
  if [[ $existing == true && ! -f "$destination/$managed_checksum" ]]; then
    printf 'Refusing to overwrite an existing plugin not managed by this installer: %s\n' "$destination" >&2
    exit 1
  fi
  if [[ -f "$destination/$managed_checksum" ]]; then
    declare -A seen_checksums=()
    checksum_valid=true
    while read -r digest filename extra || [[ -n ${digest:-}${filename:-}${extra:-} ]]; do
      if [[ ! $digest =~ ^[[:xdigit:]]{64}$ || -z ${filename:-} || -n ${extra:-} ]]; then
        checksum_valid=false
        break
      fi
      if [[ -n ${seen_checksums[$filename]+present} ]]; then
        checksum_valid=false
        break
      fi
      managed_name=false
      for file in "${plugin_files[@]}"; do
        [[ $filename == "$file" ]] && managed_name=true
      done
      if [[ $managed_name != true ]]; then
        checksum_valid=false
        break
      fi
      seen_checksums["$filename"]=1
    done < "$destination/$managed_checksum"
    for file in "${plugin_files[@]}"; do
      [[ -n ${seen_checksums[$file]+present} ]] || checksum_valid=false
    done
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
  begin_count=$(grep -Fc -- "$marker" "$bindings" || true)
  end_count=$(grep -Fc -- "$end_marker" "$bindings" || true)
fi
if [[ $begin_count != "$end_count" || $begin_count -gt 1 ]]; then
  printf 'Refusing to modify a partial or duplicate managed shortcut block in %s\n' "$bindings" >&2
  exit 1
fi

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
  {
    printf '\n%s\n' "$marker"
    printf '%s\n' '-- o.bind registers a compositor-wide shortcut in Omarchy.'
    printf '%s\n' '-- The command toggles the plugin by its manifest id; edit the key chord if it conflicts.'
    printf '%s\n' 'o.bind('
    printf '%s\n' '  "SUPER + CTRL + SHIFT + H",'
    printf '%s\n' '  "Attached sessions",'
    printf '%s\n' '  "omarchy-shell shell toggle pvalletbo.attached"'
    printf '%s\n' ')'
    printf '%s\n' '-- END Attached session picker'
  } >> "$bindings"
fi

omarchy-shell shell rescanPlugins
omarchy plugin enable pvalletbo.attached
printf 'Installed Attached picker. Press Super+Ctrl+Shift+H to open it.\n'
