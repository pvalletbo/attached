# Attached for Omarchy

> **AI contribution notice:** This document was updated with contributions from an AI coding agent at the explicit request of the project maintainer.

The first-party-style Omarchy Shell overlay in this directory searches the sessions already synchronized by Attached and opens the selected remote Herdr session in a new terminal.

## Prerequisites

- Omarchy 4.0.1 or newer with `omarchy` and `omarchy-shell` on `PATH`.
- `attached` installed on `PATH`.
- The 1Password CLI (`op`) connected to a signed-in 1Password app.
- An Attached download account whose encrypted local state was created with `--use-1password`. Verify it with:

  ```bash
  attached --use-1password sessions --json
  ```

  An unconfigured account prints `[]`; configuration, unlock, and network errors fail with a non-zero exit code. The overlay has no controlling terminal and therefore always selects the 1Password backend. Existing password-prompt state is not automatically migrated.

## Install

From a checkout of this repository:

```bash
./integrations/omarchy/install.sh
```

The installer validates and copies only the three plugin runtime files, adds one managed shortcut block to `~/.config/hypr/bindings.lua`, rescans Omarchy Shell, and enables `pvalletbo.attached`. Re-running it is idempotent while installed files are unchanged. It refuses to overwrite an unrecognized installation, local plugin modifications, or symlinked destinations. If copying, rescanning, or enabling fails, it restores the previous plugin files and bindings.

Press **Super+Ctrl+Shift+H** to toggle the right-side picker. Type to fuzzy-filter, use **Up/Down** to move, **Enter** or a mouse click to connect, **Escape** to clear the query or dismiss, **Ctrl+R** to retry a failed refresh, and **Ctrl+O** to ask Omarchy to open or install 1Password.

## Integration contract

`attached sessions --json` is the stable machine boundary. Because Omarchy Shell cannot answer an interactive password prompt, the overlay invokes it as `attached --use-1password sessions --json`. It returns a JSON array containing only:

```json
[
  {
    "target": "host/session",
    "host": "host",
    "session": "session",
    "publishedAt": "2026-08-29T12:34:56Z"
  }
]
```

The overlay rejects malformed, oversized, and inconsistent rows before display. It passes `attached --use-1password attach <target>` to the Omarchy terminal launcher as an argv array rather than a shell string, so a target can never become shell syntax. Session and query text is rendered as plain text. Raw command stderr is not rendered in the overlay; failures become bounded guidance for opening 1Password, retrying, or running the same command in a terminal. Diagnostics report lifecycle events and counts without logging session targets or catalog payloads.

## Validate

CI runs the portable static checks:

```bash
node --test integrations/omarchy/tests/*.test.js \
  integrations/omarchy/pvalletbo.attached/tests/*.test.js
bash -n integrations/omarchy/install.sh
qmlformat integrations/omarchy/pvalletbo.attached/Overlay.qml > /dev/null
```

On an Omarchy host, also validate the plugin manifest and target-only imports:

```bash
omarchy plugin validate integrations/omarchy/pvalletbo.attached
```

The JavaScript tests cover strict catalog parsing, bounded inputs, deterministic case-insensitive fuzzy ranking, safe terminal argv construction, documentation contracts, plugin structure, and installer idempotency, rollback, and fail-closed behavior.

Static checks cannot validate the compositor or 1Password desktop integration. Before release, exercise the plugin in a real Omarchy 4.0.1 Wayland session and confirm:

- the overlay loads and follows the active theme;
- the compositor delivers **Super+Ctrl+Shift+H**;
- keyboard and mouse selection work;
- **Ctrl+O** opens or offers to install 1Password;
- a locked 1Password account can be authorized and the catalog retried;
- selecting a session launches a terminal and attaches successfully.
