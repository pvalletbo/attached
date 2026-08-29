# Attached for Omarchy

The first-party-style Omarchy Shell overlay in this directory searches the sessions already synchronized by Attached and opens the selected remote Herdr session in a new terminal.

## Prerequisites

- Omarchy 4.0.1 or newer with `omarchy` and `omarchy-shell` on `PATH`.
- `attached` installed on `PATH`.
- An Attached download account already configured. Verify it with:

  ```bash
  attached sessions --json
  ```

  An unconfigured account prints `[]`; configuration and network errors fail with a non-zero exit code.

## Install

From a checkout of this repository:

```bash
./integrations/omarchy/install.sh
```

The installer validates and copies only the three plugin runtime files, adds one managed shortcut block to `~/.config/hypr/bindings.lua`, rescans Omarchy Shell, and enables `pvalletbo.attached`. Re-running it is idempotent while installed files are unchanged. It refuses to overwrite an unrecognized installation, local plugin modifications, or symlinked destinations.

Press **Super+Ctrl+Shift+H** to toggle the right-side picker. Type to fuzzy-filter, use **Up/Down** to move, **Enter** or a mouse click to connect, **Escape** to clear the query or dismiss, and **Ctrl+R** to retry a failed refresh.

## Integration contract

`attached sessions --json` is the stable machine boundary. It returns a JSON array containing only:

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

The overlay rejects malformed, oversized, and inconsistent rows before display. It passes `attached attach <target>` to the Omarchy terminal launcher as an argv array rather than a shell string, so a target can never become shell syntax. Session and query text is rendered as plain text. Diagnostics report lifecycle events and counts without logging session targets or catalog payloads.

## Validate

Portable checks used by CI:

```bash
node --test integrations/omarchy/tests/*.test.js \
  integrations/omarchy/pvalletbo.attached/tests/*.test.js
bash -n integrations/omarchy/install.sh
omarchy plugin validate integrations/omarchy/pvalletbo.attached
```

The JavaScript tests cover strict catalog parsing, bounded inputs, deterministic case-insensitive fuzzy ranking, safe terminal argv construction, plugin structure, and installer idempotency/fail-closed behavior. The repository CI runs the Node tests. A real Omarchy/Wayland session is still required to confirm visual layout, theme integration, shortcut delivery, and terminal launch on the target machine.
