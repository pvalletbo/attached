# Attached

## Diagnostics

The CLI writes structured diagnostics to
`~/.config/attached/logs/attached.log` in addition to terminal output. Disk
diagnostics include debug-level lifecycle and synchronization events regardless
of terminal verbosity. The log directory is private (`0700`), log files are
private (`0600`), and existing symlinked, hard-linked, incorrectly owned, or
incorrectly permissioned log files are rejected rather than followed.

Logs rotate at 1 MiB and retain at most five files (`attached.log` through
`attached.log.4`). Events may contain correlation identifiers, record revisions,
skip/acceptance reasons, and host or session display names needed to diagnose
session discovery. They do not intentionally include endpoint tickets,
capability secrets, account keys, tokens, encrypted payloads, or socket paths.
Treat the files as private operational data because host and session names can
still be sensitive.

Each complete disk event is written synchronously before the logging call
returns, and runtime write failures produce a terminal warning. An abrupt
termination, operating-system crash, or power loss can still leave data that the
kernel has not committed to physical storage unwritten.
