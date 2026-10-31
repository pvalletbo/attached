# Attached discovery for herdr-app

This document was written with AI assistance at the maintainer's request.

Discover Attached SSH publishers and enroll them in herdr-core, which makes them
available to herdr-app. The legacy Herdr TUI plugin remains separate.

## Current behavior and limitations

- Discovery is enabled by default **when a copy of the mod is loaded**. It polls
  every 30 seconds and renews its worker lease every 15 seconds.
- The mod installs with `place: "none"`: no additional layout, pane, toolbar button,
  or always-visible panel is created. Open its controls as a popup when needed.
- **Closing the popup, switching away from its layout, or unloading the last copy
  stops lease renewal.** The worker stops after about 90 seconds without renewal,
  allowing a little extra time for exporter cleanup. Existing machine
  registrations and remote terminals remain available.
- This version does **not** provide invisible automatic startup or discovery that
  survives closing the last mod view for the rest of the app session. An app
  startup/background hook would be needed for automatic loading without a view.
  No LaunchAgent, systemd service, or other login service is installed.
- Core installation/upgrades are OFF on first use. The popup can explicitly enable
  `hc machine add --install` for newly discovered publishers. Saved preferences
  survive closing the popup and reinstalling the mod.

Only registrations enrolled by this integration are candidates for removal.
A registration is forgotten after three distinct, complete discovery snapshots
omit its publisher. Stale, malformed, partial, or failed discovery never counts
as proof of disappearance. Manual registrations are not adopted, and observed
manual removals are not undone. Forgetting a registration never kills its remote
terminals or uninstalls the remote core.

## Requirements

- macOS or Linux, Rust/Cargo matching this repository's `rust-toolchain.toml`.
- herdr-app and herdr-core (`hc`), tested with app 0.1.9 and core 0.1.14.
- Attached and OpenSSH on the local machine's PATH.
- An imported Attached download account with unattended credential access, such
  as an unlocked 1Password CLI or the configured password environment variable.
- A compatible remote core on publishers, unless installation/upgrades have been
  explicitly enabled in the popup.

The mod executes `attached`, `ssh`, and `hc` through its bundled worker. It reads
`~/.ssh/attached/discovery.json`, reuses an existing Attached SSH exporter when
available, or starts one it owns. It does not bypass SSH host-key verification or
prompt for credentials. JavaScript does not read account passwords or keys.

## Install

Run these commands from the root of an Attached source checkout:

```sh
APP_HOME="${HERDR_APP_HOME:-$HOME/.config/herdr-app}"

cargo build --release --locked -p attached-herdr-plugin
target/release/attached-herdr-plugin app-install "$APP_HOME"
HERDR_APP_HOME="$APP_HOME" herdr-app check "$APP_HOME/mods/attached-discovery"
```

The installer copies `main.js`, `mod.json`, this README, and a `worker` executable
into `$APP_HOME/mods/attached-discovery`. It refuses to overwrite an existing mod
folder, does not select or modify a layout, and does not start discovery itself.

Open the controls in the running app, without creating a new layout or pane:

```sh
HERDR_APP_HOME="$APP_HOME" herdr-app do mod.open --name attached-discovery
```

The command palette can invoke the same `mod.open` action. A shortcut can also
invoke it; no keybindings are installed or replaced automatically. An additional
Files/Changes-style toolbar button is not included.

For installations where the app uses a custom core binary, set
`ATTACHED_HERDR_CORE` to its absolute path in the app's launch environment. The
app's environment must also make `attached`, `ssh`, and any unattended credential
provider available.

### Optional persistent view

If continuous discovery is desired while using the app, an optional mod tab can
keep a copy loaded after it has first been shown:

```sh
HERDR_APP_HOME="$APP_HOME" herdr-app do tab.new \
  --mod attached-discovery --name "Attached discovery"
```

Alternatively, explicitly mount `content: {"mod":"attached-discovery"}` in a
personal layout block. Clone a shipped layout before changing its structure;
never edit the shipped `main` layout. A layout-owned copy stops renewing when
you switch to a layout without it. A tab/pane copy must first be shown after app
startup; do not assume a background tab provides invisible automatic startup.
These are optional loading choices, not requirements imposed by the installer.

## Check whether discovery is running

These commands are read-only and do not start or renew discovery:

```sh
APP_HOME="${HERDR_APP_HOME:-$HOME/.config/herdr-app}"
STATE="$APP_HOME/data/attached-discovery"

# Check for the installed worker process.
pgrep -fl 'attached-discovery/worker app-run'

# Last completed check; jq is optional, not a runtime dependency of the mod.
jq '{running, managed, checked_at, error}' "$STATE/status.json"

# Is a loaded view still renewing discovery?
jq '{enabled, install_core, heartbeat_age_seconds: ((now - .checked_at) | floor)}' \
  "$STATE/lease.json"

# Recent diagnostics.
tail -n 30 "$STATE/discovery.log"
```

Without `jq`, inspect the JSON using, for example,
`python3 -m json.tool "$STATE/status.json"` and
`python3 -m json.tool "$STATE/lease.json"`.

Interpretation:

- A matching worker process plus a heartbeat age below roughly 30 seconds means
  a mod copy is loaded and actively renewing discovery. If multiple app homes
  exist, confirm that the worker's arguments point at the expected state folder.
- `enabled: false` means discovery has been paused. An old lease can still say
  `enabled: true`; its timestamp is what determines expiry.
- `running` is the worker's last persisted report. It can be stale after a crash,
  so do not rely on that field alone: check the process and lease too.
- `checked_at` is a Unix timestamp. It can be `null` during the first check, and
  can remain unchanged while a slow SSH enrollment is in progress.
- `managed` counts only auto-enrolled registrations, excluding manual machines.
- `error: null` means the latest completed cycle reported no error. Failed
  enrollments are retried with backoff; see the log for their details.
- Missing state files normally mean the mod has never been activated, or its
  local state was removed.

For machine connectivity rather than discovery-worker health, use
`hc machine ls --json`. For app/mod loading errors, use
`HERDR_APP_HOME="$APP_HOME" herdr-app status`. Connected machines alone do not
prove discovery is still running.

Do not use `worker app-heartbeat` as a status command: it renews the lease and can
start the worker, changing the state you are trying to inspect.

## Pause, resume, and update

Use **Pause** or **Resume** in the popup. Pause is stored in the app's shared
preferences and applies to every copy. It does not remove saved machines.

To update, unload all copies, follow the stop-and-remove steps below, rebuild,
and run the installation commands again. Keep the state directory if ownership
history and suppression of manual removals should survive the update.

## Uninstall

1. Close the Attached popup. Remove any optional mod tabs, panes, or layout
   blocks that you deliberately added. Do not remove unrelated terminals or
   shipped layout files. A still-loaded copy can renew the lease again.
2. Stop the worker using the installed helper, after unloading all copies:

   ```sh
   APP_HOME="${HERDR_APP_HOME:-$HOME/.config/herdr-app}"
   STATE="$APP_HOME/data/attached-discovery"
   "$APP_HOME/mods/attached-discovery/worker" app-pause "$STATE"
   ```

   If the helper is unavailable, unloading every copy and waiting for the
   90-second lease to expire also stops discovery. Graceful exporter cleanup can
   take a few additional seconds. Only an exporter owned by this worker is
   stopped; an existing TUI/user exporter is left alone.
3. Use the process/status checks above to confirm that this app home's worker
   has exited. **Do not delete its state directory while it is still running.**
4. Remove only the installed mod folder:

   ```sh
   rm -r -- "$APP_HOME/mods/attached-discovery"
   ```

5. Optionally remove its saved ownership, lease, status, and logs:

   ```sh
   rm -r -- "$STATE"
   ```

   Keeping this directory preserves ownership history for a future reinstall.
   Deleting it does not delete any machine registration. The app's shared
   preferences are also retained; do not edit or remove `shared.json` just to
   uninstall this mod.

Uninstalling leaves registered machines and their remote terminals untouched.
If you also want to forget a registration, review `hc machine ls --json` and run
`hc machine rm <machine-name> --json` for each chosen entry. Do not bulk-remove
manual registrations. This integration does not uninstall Attached, delete SSH
trust, change accounts, or remove the legacy TUI plugin.

## Removal safety limitation in herdr-core

The worker verifies the recorded name, core id, SSH target, transport and session
before forgetting a registration. However, hc removes by name and has no atomic
conditional-delete API. An identical manual remove/re-add entirely between
checks, or an identical-name replacement racing the final check and removal,
cannot be distinguished. Eliminating that race requires registration identities
or conditional removal support in herdr-core.
