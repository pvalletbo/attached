# Attached for Omarchy

> **AI contribution notice:** This document was updated with contributions from an AI coding agent at the explicit request of the project maintainer.

The first-party-style Omarchy Shell overlay in this directory searches the sessions already synchronized by Attached and opens the selected remote Herdr session in a new terminal.

## Prerequisites

- Omarchy 4.0.1 or newer with `omarchy` and `omarchy-shell` on `PATH`.
- `attached` installed on `PATH`.
- An Attached download account. Verify password-backed state with `attached sessions --json`, or state created with `--use-1password` with `attached --use-1password sessions --json`.

An unconfigured account prints `[]`; configuration, unlock, and network errors fail with a non-zero exit code. 1Password is optional.

## Install

From a checkout of this repository:

```bash
./integrations/omarchy/install.sh
```

The installer validates and copies only the three plugin runtime files, adds one managed shortcut block to `~/.config/hypr/bindings.lua`, creates `~/.config/attached/omarchy.json` when it does not exist, rescans Omarchy Shell, and enables `pvalletbo.attached`. Re-running it is idempotent while installed files are unchanged, and it never overwrites the user-owned provider configuration. It refuses to overwrite an unrecognized installation, local plugin modifications, or symlinked destinations. If copying, rescanning, or enabling fails, it restores the previous plugin files and bindings and removes any configuration created by the failed attempt.

The default configuration uses the regular encryption password:

```json
{
  "encryptionPasswordProvider": "password"
}
```

Set `encryptionPasswordProvider` to `"1password"` to use the 1Password CLI instead. Existing encrypted state is not migrated when this setting changes, so select the provider that was used to create it.

Press **Super+Ctrl+Shift+H** to toggle the centered command palette. With the default provider, enter the encryption password first. The host is the primary result label; the session name, Attached version, Herdr version, and last-publish age appear as smaller supporting information. Type to fuzzy-filter, use **Up/Down** to move, **Enter** or a mouse click to connect, **Escape** to clear the query or dismiss, and **Ctrl+R** to retry a failed refresh. With the 1Password provider, **Ctrl+O** asks Omarchy to open or install 1Password.

## Integration contract

`attached sessions --json` is the stable machine boundary. Omarchy Shell has no controlling terminal, so the default provider invokes it as `attached sessions --json --password-stdin` and writes the password to the process's anonymous standard-input pipe. The password is not placed in arguments or environment variables and is cleared from the overlay immediately after writing. The configured 1Password provider instead invokes `attached --use-1password sessions --json`. Both return a JSON array containing only:

```json
[
  {
    "target": "host/session",
    "host": "host",
    "session": "session",
    "attachedVersion": [0, 3, 1],
    "herdrVersion": [0, 9, 0],
    "publishedAt": "2026-08-29T12:34:56Z"
  }
]
```

The overlay rejects malformed, oversized, and inconsistent rows before display. It passes `attached attach <target>` to the Omarchy terminal launcher for password-backed state, where Attached prompts again in the new terminal. It adds `--use-1password` only for the configured 1Password provider. Both commands are argv arrays rather than shell strings, so a target can never become shell syntax. Session and query text is rendered as plain text. Raw command stderr is not rendered in the overlay; failures become bounded provider-specific guidance. Diagnostics report lifecycle events and counts without logging session targets, passwords, or catalog payloads.

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

The JavaScript tests cover strict catalog parsing, bounded inputs, provider configuration, deterministic case-insensitive fuzzy ranking, safe terminal argv construction, documentation contracts, plugin structure, and installer idempotency, rollback, and fail-closed behavior.

Static checks cannot validate the compositor or desktop password interactions. Before release, exercise the plugin in a real Omarchy 4.0.1 Wayland session and confirm:

- the overlay loads and follows the active theme;
- the compositor delivers **Super+Ctrl+Shift+H**;
- a typed encryption password refreshes password-backed state without appearing in process arguments;
- keyboard and mouse selection work;
- with the 1Password provider, **Ctrl+O** opens or offers to install 1Password;
- a locked 1Password account can be authorized and the catalog retried;
- selecting a session launches a terminal and attaches successfully with either provider.
