# Attached

Discover remote machines and connect over SSH through encrypted [Iroh](https://www.iroh.computer/)
tunnels, without configuring inbound ports, a VPN, or a system SSH daemon.

Attached provides host discovery, credentials, and the SSH connection. Applications such as Herdr
use that connection to discover and manage their own sessions; Attached does not inspect, launch,
upgrade, or proxy Herdr sessions.

> Alpha software: host discovery and remote-update protocols may change between releases.
> Use matching current Attached versions on the client and publishers.

## Install

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://install.attached.sh | sh
```

Or build from source:

```bash
cargo install --git https://github.com/pvalletbo/attached.git --locked attached
```

Run `attached --version` to verify the installation. The client needs OpenSSH (`ssh` and
`ssh-keygen`). [fzf](https://junegunn.github.io/fzf/) is optional, for choosing a host during remote
Attached updates. Linux and macOS are supported.

## Connect to your first machine

On the **client**:

```bash
# Create an account and protect local credentials with an encryption password.
attached account create

# Copy a publish-only bundle to the clipboard temporarily.
attached account export --type publish
```

On the **publisher**:

```bash
# Paste the publish bundle when prompted. Keep this process running.
attached serve --host-label office
```

After the bundle has been saved, run this in a second terminal on the publisher:

```bash
# Explicitly authorize remote command execution as the current OS user.
attached ssh-access enable
```

Back on the client:

```bash
# Lists SSH-enabled machines, not application sessions.
attached sessions list

# Execute a command. Its exit status is returned by Attached.
attached ssh office uname -a

# Or open a non-PTY shell.
attached ssh office
```

SSH access is disabled until explicitly enabled. Permission persists across server restarts.
Discovery is republished every 30 seconds, so enabling or disabling access may take up to that long
to appear in a freshly fetched list. The server enforces the current permission independently of
discovery. To revoke access:

```bash
attached ssh-access disable
```

New connections are rejected and active SSH connections are cancelled within one second.
Deliberately detached remote processes cannot be recalled.

For headless provisioning, export a bundle with `attached account export --type publish --output
publish.bundle`, transfer it securely, and pass `--bundle-file publish.bundle` to `attached serve`.
The `ATTACHED_PUBLISH_BUNDLE` environment variable is also supported. Bundle files are secrets;
export creates a new owner-only file and refuses to overwrite an existing file.

## Discovery and application integration

`attached sessions list` always refreshes discovery and displays:

- **HOST**: the publisher's human-readable label;
- **ENDPOINT ID**: its stable Iroh identity, also usable as an SSH or update target;
- **ATTACHED**: the running Attached version;
- **LAST PUBLISH**: the age of the latest authenticated advertisement.

Only unexpired, SSH-enabled publishers are listed. Advertisements expire after 90 seconds;
a listed machine is not a guarantee that a live connection will succeed. Locally running Attached
endpoints are omitted from the remote listing. Labels can collide: use the full endpoint ID to
select a particular machine. Ambiguous labels are rejected rather than selected arbitrarily.

`attached ssh` reuses recent discovery without extending a publisher's lease. Use `--no-cache`
to force a refresh. Long-lived brokers renew their selected publisher by stable identity when a
new SSH connection needs fresh connection details; existing byte streams do not depend on renewal.

For clients that already know how to invoke OpenSSH, expose a temporary configuration:

```bash
# Prints a configuration path, then stays in the foreground until Ctrl-C.
attached ssh --expose-config office

# In another terminal, using the printed path and the host's endpoint ID:
ssh -F /printed/path/config attached-ENDPOINT-ID 'your-remote-command'
```

The broker creates connection-scoped client keys, pins the publisher's SSH identity, and transports
SSH over Iroh through a private local proxy socket. It does not modify `~/.ssh/config` or
`authorized_keys`. Keep the broker running while its configuration is in use. Its temporary files
are removed when it exits normally.

Use one broker for concurrent connections to a publisher: separate Attached processes share the
consumer Iroh identity and can displace each other on relays. The current SSH service supports
command execution and non-PTY shells, not PTYs, SFTP, agent forwarding, or TCP forwarding.
Applications own any session discovery, installation checks, and lifecycle operations they run over
SSH. Attached's old `attach`, `--herdr-bin`, and `--upgrade-remote` interfaces are removed.

## Accounts and local configuration

Credentials and the persistent endpoint identity are stored under `$HOME/.config/attached` by
default. Private keys, account bundles, the host catalog, and the publisher's SSH host key are
encrypted at rest. Host pins and SSH consent policy are owner-only metadata files.

To add another client:

```bash
attached account export --type download --output download.bundle
# Transfer the file securely, then on the new client:
attached account import --bundle-file download.bundle
```

`attached account import --bundle-stdin` is available for automation. Publish bundles cannot be
used as download bundles and do not contain the consumer's private Iroh identity.

Attached reads `$HOME/.config/attached/config.toml`:

```toml
password_source = "password" # or "1password"
# config_directory = "/absolute/path/to/attached-state"
```

`--use-1password` overrides the password source for an invocation. Noninteractive SSH calls fail
rather than prompting for a password on the application's data stream; configure 1Password for
unattended use. Run `attached --help` for global diagnostics and completion options.

## Updates and removal

```bash
attached update                   # Update locally (alias: upgrade).
attached update --remote office   # Update a publisher by label or endpoint ID.
attached update --remote          # Choose a remote host with fzf.
attached uninstall               # Remove Attached and managed local state.
```

Remote updates retain the authenticated, fixed-operation update service: stage the latest release,
prepare a replacement server, hand off the endpoint identity and credentials over private IPC,
and commit only after client reconnection. Failed handoffs restore the previous server and binary.
Remote updates now address machines, not `HOST/SESSION`. They do not require arbitrary-shell consent;
an explicitly named publisher can still be updated when SSH access is disabled. Active SSH
connections are interrupted by an update and must be re-established.

This host-only release changes encrypted discovery descriptors and the remote-update protocol;
old Attached peers are not supported. Existing account credentials and endpoint identities are
retained. The rebuildable discovery cache is now `host-catalog.json`; the old `sync-catalog.json`
is no longer read. Upgrade both ends locally when crossing this protocol change.

## How it works and security

Iroh uses public-key endpoint identities, address lookup, NAT traversal, and relay fallback to
establish end-to-end encrypted QUIC connections. See the [Iroh endpoint documentation](https://docs.iroh.computer/concepts/endpoints).

The passive synchronization backend stores authenticated, encrypted host descriptors containing
the host label, endpoint ticket, tunnel capability, Attached version, SSH permission advertisement,
and publication/expiration times. It cannot decrypt those descriptors. The existing hosted service
URL remains `https://herdr.attached.sh`; that domain name does not imply a Herdr dependency.
Use `attached account create --service https://your-service.example` to choose a self-hosted service.
The Cloudflare Worker and its credential/storage machinery remain in `crates/session-sync-worker`.

Connection admission checks the account's authorized consumer Iroh identity before application
traffic. SSH additionally checks the tunnel capability, explicit publisher consent, a connection-scoped
client key, and the publisher's pinned SSH host key. A changed host key or OS account fails closed;
use `--trust-new-host-key` only after independently verifying the change.

Important limitations:

- An authorized consumer can execute arbitrary commands as the publisher's OS account. Treat
  download/owner bundles and their decryption credentials as remote-shell-equivalent secrets.
- A compromised synchronization service can hide records, deny service, or replay valid
  advertisements until expiration. Authenticated encryption is not an availability guarantee.
- Account publishers share the descriptor encryption key. That key alone does not grant consumer
  Iroh identity or SSH permission; do not treat a publish-only bundle as harmless.
- SSH revocation is local to each publisher. General account-token revocation and per-client
  identities are not yet implemented.

## Development

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo deny check bans licenses sources
```

The workspace contains the CLI, encrypted discovery protocol, synchronization Worker, and SSH/update
tunnel protocol. The former experimental browser client, Herdr TUI protocol, and combined
Attached/Herdr runtime image have been removed.

This document was updated with AI assistance.
