# Attached

## Serving sessions

`attached serve` publishes the host's active Herdr sessions. If Herdr has not
been started yet and discovery returns no active sessions, Attached starts the
default session with `herdr server`, waits up to five seconds for it to become
discoverable, and only then publishes the initial catalog. The headless Herdr
server is placed in its own process group and continues running independently.

Startup failures are reported before the host is advertised. Use `-v` to see
the structured lifecycle events for automatic default-session startup.
