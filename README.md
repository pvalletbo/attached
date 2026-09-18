# Attached

Attached provides a simple way to attach to remote Herdr sessions without requiring any open SSH port. 
It uses the new remote machines feature added in Herdr 0.9.0, which uses SSH to control the remote 
hosts, but hiding the complexity of managing SSH keys and networking details by using ephemeral 
SSH keys and peer to peer tunnels using [Iroh](https://www.iroh.computer/).

![Attached setup and remote machine access in Herdr](demo/attached-demo.gif)

## Install

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://install.attached.sh | sh
```

Or build from source:

```bash
cargo install --git https://github.com/pvalletbo/attached.git --locked attached
```

Run `attached --version` to verify the installation. The client needs OpenSSH (`ssh` and
`ssh-keygen`). Linux and macOS are supported.

## 1Password support

Attached can use [1Password](https://1password.com/) to generate and store its local encryption
password instead of asking you to enter one. Install the
[1Password CLI](https://developer.1password.com/docs/cli/get-started/) and make sure `op` is available
on your PATH and authenticated, with 1Password unlocked when Attached needs it.

To use 1Password by default on a machine, create or edit `$HOME/.config/attached/config.toml`:

```toml
password_source = "1password"
```

Attached reads this setting on each invocation, so you do not need to pass `--use-1password` every
time. The configuration file contains no password; Attached retrieves it through `op`. If 1Password
is unavailable, the operation fails rather than falling back to a manually entered password.

For a new setup, configure this before `attached account create` or the first `attached serve`.
Attached creates an **Attached encryption password** item if one does not already exist, then
reuses it. Changing this setting does not migrate or re-encrypt credentials already protected with
a manually chosen password.

For a single invocation without changing the configuration, use the `--use-1password` flag.

## Connect to your first machine

On the **client**:

```bash
# Create an account and protect local credentials with an encryption password.
attached account create

# Copy a publish-only bundle to the clipboard temporarily.
attached account export --type publish
```

On the **remote machine**:

```bash
# Paste the publish bundle when prompted. Keep this process running.
attached serve --host-label office
```

Back on the client:

```bash
# One one terminal expose the remote attached clients to the local SSH client
attached export-ssh-config

# On another terminal add the new host to Herdr
herdr machine add attached-office --label Office

# Now you are ready to open Herdr and connect to the remote machine
herdr
```

## How it works

You must have two available hosts:

* **Client**: the local host from which you will control the remote session
* **Publisher**: the remote host running `attached serve` and providing SSH access to the client.
  This may be any machine that can run Attached, including a Docker container. An active Herdr
  session is not required.

### Establishing the tunnel


To connect to a remote machine, the client first establishes a secure peer-to-peer (P2P) channel.
Attached uses [Iroh](https://www.iroh.computer/) to create an end-to-end encrypted QUIC connection
rather than implementing its own networking layer. The tunnel protects the bytes exchanged between
the client and publisher from the synchronization service, relays, and other network observers.
See the [Iroh endpoint documentation](https://docs.iroh.computer/concepts/endpoints) for more detail.

The client needs enough information to identify the publisher and request a connection. In a
traditional HTTP exchange this would be an IP address, but IP addresses can change. Iroh instead
uses public-key endpoint identities. Both sides have public/private key pairs, and the publisher's
identity is used for address lookup. Iroh attempts NAT traversal to establish a direct connection
and falls back to a relay when the peers cannot reach one another directly. The connection remains
end-to-end encrypted in either case.

### Sharing discovery information

The publisher and client must also share the information needed to establish the tunnel. The
publisher encrypts and authenticates a host descriptor, then uploads it to the passive
synchronization service. The client retrieves and decrypts the descriptor using the account
credentials shared out of band by `attached account export`. The service cannot decrypt the
contents or forge modified descriptors that pass authentication. It can still overwrite, delete,
withhold, or replay stored ciphertext.

The following machine-level information is shared:

* **Host label**: a descriptive name for the host
* **Iroh endpoint ticket**: used by the consumer to establish the P2P tunnel
* **Tunnel capability**: a shared secret that the consumer must present to authorize the tunnel
* **Attached version**: the running version of the Attached binary
* **SSH-enabled status**: whether the publisher advertises SSH access
* **Publication and expiration times**: when the descriptor was issued and when it stops being valid

Attached does not publish Herdr versions or session names. Herdr discovers and manages its own
sessions over SSH after connecting to the machine.

### Security model and limitations

If private keys and encryption keys are not leaked, the design provides these protections:

- **A third party cannot read the connection.** Iroh's end-to-end encryption protects traffic
  between the client and publisher, including when a relay is used.
- **The synchronization service cannot connect to a publisher.** It can store and return
  advertisements, but it does not possess the consumer's private Iroh identity or the credentials
  required to pass connection admission.
- **The synchronization service cannot make the client connect to an arbitrary publisher.** Host
  descriptors are authenticated and encrypted with a key shared by the account, and SSH also pins
  the publisher's SSH host identity.
- **A publish-only bundle does not grant consumer access.** Account publishers share the descriptor
  encryption key, but that key alone does not grant the consumer Iroh identity or SSH permission.
- **Sensitive local data is encrypted at rest.** Private keys, account bundles, discovery data, and
  other credentials are protected by the local encryption password or configured password provider.

Running `attached serve` with a valid publish bundle automatically enables SSH for that bundle's
authorized consumer as the publisher's current OS account; there is no separate enable step.
Before application traffic is admitted, Attached checks the account's authorized consumer Iroh
identity. SSH additionally checks the tunnel capability, a connection-scoped client key, and the
publisher's pinned SSH host key.

Important limitations:

- An authorized consumer can execute arbitrary commands as the publisher's OS account. Treat
  download/owner bundles and their decryption credentials as remote-shell-equivalent secrets.
- A compromised synchronization service can hide records, deny service, or replay valid
  advertisements until expiration. Authenticated encryption is not an availability guarantee.
- To end SSH access, stop `attached serve` on each publisher. This does not undo commands or
  terminate deliberately detached processes. General account-token revocation and per-client
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
