# Attached

Attached provides a simple way to attach to remote Herdr sessions without requiring any open SSH port. 
It uses the new remote machines feature added in Herdr 0.9.0, which uses SSH to control the remote 
hosts, but hiding the complexity of managing SSH keys and networking details by using ephemeral 
SSH keys and peer to peer tunnels using [Iroh](https://www.iroh.computer/).

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

Back on the client:

```bash
# Lists SSH-enabled machines, not application sessions.
attached sessions list

# Execute a command. Its exit status is returned by Attached. This confirms that SSH works on the remote host through the P2P tunnel
attached ssh office uname -a
```

## Discovery and application integration

`attached sessions list` always refreshes discovery and displays:

- **HOST**: the publisher's human-readable label;
- **ENDPOINT ID**: its stable Iroh identity, also usable as an SSH or update target;
- **ATTACHED**: the running Attached version;
- **LAST PUBLISH**: the age of the latest authenticated advertisement.


```bash
# Prints a configuration path, then stays in the foreground until Ctrl-C.
attached ssh --expose-config

# In another terminal, using the printed path and the host's endpoint ID:
ssh attached-ENDPOINT-ID 'your-remote-command'
```

Since the machine is accessible as any other SSH remote host, this means that the new machine 
can be added to Herdr in order to make it appear in the machines list. Run this: 

```bash
herdr machine add attached-ENDPOINT-ID --label NewMachine
```

You should see the new machine in the machines list within your running Herdr client.

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
